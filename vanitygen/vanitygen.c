/*
 * Vanitygen, vanity bitcoin address generator
 * Copyright (C) 2011 <samr7@cs.washington.edu>
 *
 * Vanitygen is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version. 
 *
 * Vanitygen is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Vanitygen.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>

#include <pthread.h>

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "pattern.h"
#include "util.h"

const char *version = VANITYGEN_VERSION;

void *vg_thread_loop(void *arg)
{
    unsigned char hash_buf[128];
    unsigned char *eckey_buf;
    unsigned char hash1[32];

    int i, c, len, output_interval;
    int hash_len;

    const BN_ULONG rekey_max = 10000000;
    BN_ULONG npoints, rekey_at, nbatch;

    vg_context_t *vcp = (vg_context_t *) arg;
    EC_KEY *pkey = NULL;
    const EC_GROUP *pgroup;
    const EC_POINT *pgen;
    const int ptarraysize = 256;
    EC_POINT *ppnt[ptarraysize];
    EC_POINT *pbatchinc;

    vg_test_func_t test_func = vcp->vc_test;
    vg_exec_context_t ctx;
    vg_exec_context_t *vxcp;

    struct timeval tvstart;

    memset(&ctx, 0, sizeof(ctx));
    vxcp = &ctx;

    vg_exec_context_init(vcp, &ctx);

    pkey = vxcp->vxc_key;
    pgroup = EC_KEY_get0_group(pkey);
    pgen = EC_GROUP_get0_generator(pgroup);

    for (i = 0; i < ptarraysize; i++) {
        ppnt[i] = EC_POINT_new(pgroup);
        if (!ppnt[i]) {
            fprintf(stderr, "ERROR: out of memory?\n");
            exit(EXIT_FAILURE);
        }
    }
    pbatchinc = EC_POINT_new(pgroup);
    if (!pbatchinc) {
        fprintf(stderr, "ERROR: out of memory?\n");
        exit(EXIT_FAILURE);
    }

    BN_set_word(&vxcp->vxc_bntmp, ptarraysize);
    EC_POINT_mul(pgroup, pbatchinc, &vxcp->vxc_bntmp, NULL, NULL, vxcp->vxc_bnctx);
    EC_POINT_make_affine(pgroup, pbatchinc, vxcp->vxc_bnctx);

    npoints = 0;
    rekey_at = 0;
    nbatch = 0;
    vxcp->vxc_key = pkey;
    vxcp->vxc_binres[0] = vcp->vc_addrtype;
    c = 0;
    output_interval = 1000;
    gettimeofday(&tvstart, NULL);

    if (vcp->vc_format == VCF_SCRIPT) {
        hash_buf[0] = 0x51;  // OP_1
        hash_buf[1] = 0x41;  // pubkey length
        // gap for pubkey
        hash_buf[67] = 0x51;  // OP_1
        hash_buf[68] = 0xae;  // OP_CHECKMULTISIG
        eckey_buf = hash_buf + 2;
        hash_len = 69;
    } else {
        eckey_buf = hash_buf;
        hash_len = 65;
    }

    while (!vcp->vc_halt) {
        if (++npoints >= rekey_at) {
            vg_exec_context_upgrade_lock(vxcp);
            /* Generate a new random private key */
            EC_KEY_generate_key(pkey);
            npoints = 0;

            /* Determine rekey interval */
            EC_GROUP_get_order(pgroup, &vxcp->vxc_bntmp, vxcp->vxc_bnctx);
            BN_sub(&vxcp->vxc_bntmp2, &vxcp->vxc_bntmp, EC_KEY_get0_private_key(pkey));
            rekey_at = BN_get_word(&vxcp->vxc_bntmp2);
            if ((rekey_at == BN_MASK2) || (rekey_at > rekey_max))
                rekey_at = rekey_max;
            assert(rekey_at > 0);

            EC_POINT_copy(ppnt[0], EC_KEY_get0_public_key(pkey));
            vg_exec_context_downgrade_lock(vxcp);

            npoints++;
            vxcp->vxc_delta = 0;

            if (vcp->vc_pubkey_base)
                EC_POINT_add(pgroup, ppnt[0], ppnt[0], vcp->vc_pubkey_base, vxcp->vxc_bnctx);

            for (nbatch = 1; (nbatch < ptarraysize) && (npoints < rekey_at); nbatch++, npoints++) {
                EC_POINT_add(pgroup, ppnt[nbatch], ppnt[nbatch - 1], pgen, vxcp->vxc_bnctx);
            }

        } else {
            /*
             * Common case
             *
             * EC_POINT_add() can skip a few multiplies if
             * one or both inputs are affine (Z_is_one).
             * This is the case for every point in ppnt, as
             * well as pbatchinc.
             */
            assert(nbatch == ptarraysize);
            for (nbatch = 0; (nbatch < ptarraysize) && (npoints < rekey_at); nbatch++, npoints++) {
                EC_POINT_add(pgroup, ppnt[nbatch], ppnt[nbatch], pbatchinc, vxcp->vxc_bnctx);
            }
        }

        /*
         * The single most expensive operation performed in this
         * loop is modular inversion of ppnt->Z.  There is an
         * algorithm implemented in OpenSSL to do batched inversion
         * that only does one actual BN_mod_inverse(), and saves
         * a _lot_ of time.
         *
         * To take advantage of this, we batch up a few points,
         * and feed them to EC_POINTs_make_affine() below.
         */

        EC_POINTs_make_affine(pgroup, nbatch, ppnt, vxcp->vxc_bnctx);

        for (i = 0; i < nbatch; i++, vxcp->vxc_delta++) {
            /* Hash the public key */
            len = EC_POINT_point2oct(pgroup, ppnt[i], POINT_CONVERSION_UNCOMPRESSED, eckey_buf, 65, vxcp->vxc_bnctx);
            assert(len == 65);

            SHA256(hash_buf, hash_len, hash1);
            RIPEMD160(hash1, sizeof(hash1), &vxcp->vxc_binres[1]);

            switch (test_func(vxcp)) {
                case 1:
                    npoints = 0;
                    rekey_at = 0;
                    i = nbatch;
                    break;
                case 2:
                    goto out;
                default:
                    break;
            }
        }

        c += i;
        if (c >= output_interval) {
            output_interval = vg_output_timing(vcp, c, &tvstart);
            if (output_interval > 250000)
                output_interval = 250000;
            c = 0;
        }

        vg_exec_context_yield(vxcp);
    }

out:
    vg_exec_context_del(&ctx);
    vg_context_thread_exit(vcp);

    for (i = 0; i < ptarraysize; i++)
        if (ppnt[i])
            EC_POINT_free(ppnt[i]);
    if (pbatchinc)
        EC_POINT_free(pbatchinc);
    return NULL;
}

#if !defined(_WIN32)
int count_processors(void)
{
    FILE *fp;
    char buf[512];
    int count = 0;

    fp = fopen("/proc/cpuinfo", "r");
    if (!fp)
        return -1;

    while (fgets(buf, sizeof(buf), fp)) {
        if (!strncmp(buf, "processor\t", 10))
            count += 1;
    }
    fclose(fp);
    return count;
}
#endif

int start_threads(vg_context_t *vcp, int num_threads)
{
    int err = 0;
    int i;
    pthread_t *threads;

    threads = calloc(num_threads, sizeof(pthread_t));
    if (!threads) {
        fprintf(stderr, "ERROR: Out of memory for thread allocation\n");
        return -1;
    }

    for (i = 0; i < num_threads; i++) {
        err = pthread_create(&threads[i], NULL, vg_thread_loop, vcp);
        if (err) {
            fprintf(stderr, "ERROR: Unable to create thread: %s\n", strerror(err));
            return err;
        }
    }

    for (i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    return 0;
}
