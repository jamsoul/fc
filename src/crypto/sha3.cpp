#include <fc/crypto/hex.hpp>
#include <fc/fwd_impl.hpp>
#include <openssl/sha.h>
#include <string.h>
#include <fc/crypto/sha3.hpp>
#include <fc/variant.hpp>
#include <vector>
#include "_digest_common.hpp"

namespace fc
{

sha3::sha3() { memset( _hash, 0, sizeof(_hash) ); }
sha3::sha3( const string& hex_str ) {
   auto bytes_written = fc::from_hex( hex_str, (char*)_hash, sizeof(_hash) );
   if( bytes_written < sizeof(_hash) )
      memset( (char*)_hash + bytes_written, 0, (sizeof(_hash) - bytes_written) ); 
}

string sha3::str()const {
  return fc::to_hex( (char*)_hash, sizeof(_hash) );
}
sha3::operator string()const { return  str(); }

char* sha3::data() { return (char*)&_hash[0]; }
const char* sha3::data()const { return (char*)&_hash[0]; }


struct sha3::encoder::impl {
   SHA_CTX ctx;
};

sha3::encoder::~encoder() {}
sha3::encoder::encoder() {
  reset();
}

sha3 sha3::hash( const char* d, uint32_t dlen ) {
  encoder e;
  e.write(d,dlen);
  return e.result();
}
sha3 sha3::hash( const string& s ) {
  return hash( s.c_str(), s.size() );
}

void sha3::encoder::write( const char* d, uint32_t dlen ) {
  printf("sha3::encoder::write\n");
// SHA1_Update( &my->ctx, d, dlen);
}
sha3 sha3::encoder::result() {
  sha3 h;
  printf("sha3::encoder::result\n");
  //SHA1_Final((uint8_t*)h.data(), &my->ctx );
  return h;
}
void sha3::encoder::reset() {
  printf("sha3::encoder::reset\n");
//  SHA1_Init( &my->ctx);
}

sha3 operator << ( const sha3& h1, uint32_t i ) {
  sha3 result;
  fc::detail::shift_l( h1.data(), result.data(), result.data_size(), i );
  return result;
}
sha3 operator ^ ( const sha3& h1, const sha3& h2 ) {
  sha3 result;
  result._hash[0] = h1._hash[0] ^ h2._hash[0];
  result._hash[1] = h1._hash[1] ^ h2._hash[1];
  result._hash[2] = h1._hash[2] ^ h2._hash[2];
  result._hash[3] = h1._hash[3] ^ h2._hash[3];
  result._hash[4] = h1._hash[4] ^ h2._hash[4];
  return result;
}
bool operator >= ( const sha3& h1, const sha3& h2 ) {
  return memcmp( h1._hash, h2._hash, sizeof(h1._hash) ) >= 0;
}
bool operator > ( const sha3& h1, const sha3& h2 ) {
  return memcmp( h1._hash, h2._hash, sizeof(h1._hash) ) > 0;
}
bool operator < ( const sha3& h1, const sha3& h2 ) {
  return memcmp( h1._hash, h2._hash, sizeof(h1._hash) ) < 0;
}
bool operator != ( const sha3& h1, const sha3& h2 ) {
  return memcmp( h1._hash, h2._hash, sizeof(h1._hash) ) != 0;
}
bool operator == ( const sha3& h1, const sha3& h2 ) {
  return memcmp( h1._hash, h2._hash, sizeof(h1._hash) ) == 0;
}

  void to_variant( const sha3& bi, variant& v )
  {
     v = std::vector<char>( (const char*)&bi, ((const char*)&bi) + sizeof(bi) );
  }
  void from_variant( const variant& v, sha3& bi )
  {
    std::vector<char> ve = v.as< std::vector<char> >();
    if( ve.size() )
    {
        memcpy(&bi, ve.data(), fc::min<size_t>(ve.size(),sizeof(bi)) );
    }
    else
        memset( &bi, char(0), sizeof(bi) );
  }

} // fc
