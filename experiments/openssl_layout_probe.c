/* Print the private OpenSSL layout fields used by the offline TLS extractor.
 *
 * This is compiled against the exact OpenSSL source release and distribution
 * configuration used by the target.  It is a profile-construction aid, not a
 * program that is injected into the captured Tor process.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "ssl/ssl_local.h"

int
main(void)
{
  printf("ssl.version=%zu\n", offsetof(struct ssl_st, version));
  printf("ssl.server=%zu\n", offsetof(struct ssl_st, server));
  printf("ssl.session=%zu\n", offsetof(struct ssl_st, session));
  printf("session.cipher=%zu\n", offsetof(struct ssl_session_st, cipher));
  printf("cipher.id=%zu\n", offsetof(struct ssl_cipher_st, id));
  printf("ssl.client_random=%zu\n", offsetof(struct ssl_st, s3.client_random));
  printf("ssl.client_app_traffic_secret=%zu\n",
         offsetof(struct ssl_st, client_app_traffic_secret));
  printf("ssl.server_app_traffic_secret=%zu\n",
         offsetof(struct ssl_st, server_app_traffic_secret));
  printf("ssl.read_iv=%zu\n", offsetof(struct ssl_st, read_iv));
  printf("ssl.write_iv=%zu\n", offsetof(struct ssl_st, write_iv));
  printf("ssl.read_sequence=%zu\n",
         offsetof(struct ssl_st, rlayer.read_sequence));
  printf("ssl.write_sequence=%zu\n",
         offsetof(struct ssl_st, rlayer.write_sequence));
  return 0;
}
