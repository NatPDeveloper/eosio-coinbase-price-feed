#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>
#include <eosio/crypto.hpp>
#include <eosio/print.hpp>

using namespace eosio;
using namespace std;

CONTRACT oracle : public eosio::contract {
  using contract::contract;
  public:

  // 04 prefix, coinbse uncompressed key
  const string uncompressed_key = "044170a2083dccbc2be253885a8d0e9f7ce859eb370d0c5cae3b6994af4cb9d6663e1c135774a355e78570fc76579402a6657b58c4a1ccc73237c7244297a48cfb";
  const string api_type = "prices";
  // "\x19Ethereum Signed Message:\n32"
  const string preamble_hex = "19457468657265756d205369676e6564204d6573736167653a0a3332";

  [[eosio::action]] void update(
    vector<string> messages, 
    vector<string> signatures
  ) {
    verify_signatures(messages, signatures);
  }

  private:

  using bytes = vector<char>;
  
  struct message_t {
    string type;
    uint64_t timestamp;
    string symbol;
    uint64_t price;
  };

  void verify_signatures(
    vector<string> messages, 
    vector<string> signatures
  ) {
    for(int i = 0; i < signatures.size(); i++) {
      string message = messages[i];
      string signature = signatures[i];

      check(message.size() == 512, "msg length != 512");
      check(signature.size() == 130, "sig length != 130");

      checksum256 message_hash = hash(message);
      string message_hash_string = hex_to_string(message_hash);

      validate_signature(hash(preamble_hex + message_hash_string),signature);

      message_t unpacked_message = unpack(message);
      update_data(unpacked_message);
    }
  }

  bool check_timetamp_age(uint64_t timestamp, string expected_symbol) {
    if(timestamp < current_time_point().sec_since_epoch() - (60 * 60)) {
      print(expected_symbol);
      return false;
    }
    return true;
  }

  void update_data(message_t message) {
    if(message.symbol == "BTC") {
      btc_t singleton(_self, _self.value);
      btc current = singleton.get_or_default();
      if(check_timetamp_age(message.timestamp,message.symbol) && message.timestamp > current.data.timestamp){
        btc new_price;
        new_price.data.price = message.price;
        new_price.data.timestamp = message.timestamp;
        singleton.set(new_price, _self);
      }
    } else if(message.symbol == "ETH") {
      eth_t singleton(_self, _self.value);
      eth current = singleton.get_or_default();
      if(check_timetamp_age(message.timestamp,message.symbol) && message.timestamp > current.data.timestamp){
        eth new_price;
        new_price.data.price = message.price;
        new_price.data.timestamp = message.timestamp;
        singleton.set(new_price, _self);
      }
    } else if(message.symbol == "XTZ") {
      xtz_t singleton(_self, _self.value);
      xtz current = singleton.get_or_default();
      if(check_timetamp_age(message.timestamp,message.symbol) && message.timestamp > current.data.timestamp){
        xtz new_price;
        new_price.data.price = message.price;
        new_price.data.timestamp = message.timestamp;
        singleton.set(new_price, _self);
      }
    } else if(message.symbol == "DAI") {
      dai_t singleton(_self, _self.value);
      dai current = singleton.get_or_default();
      if(check_timetamp_age(message.timestamp,message.symbol) && message.timestamp > current.data.timestamp){
        dai new_price;
        new_price.data.price = message.price;
        new_price.data.timestamp = message.timestamp;
        singleton.set(new_price, _self);
      }
    } else if(message.symbol == "REP") {
      rep_t singleton(_self, _self.value);
      rep current = singleton.get_or_default();
      if(check_timetamp_age(message.timestamp,message.symbol) && message.timestamp > current.data.timestamp){
        rep new_price;
        new_price.data.price = message.price;
        new_price.data.timestamp = message.timestamp;
        singleton.set(new_price, _self);
      }
    } else if(message.symbol == "ZRX") {
      zrx_t singleton(_self, _self.value);
      zrx current = singleton.get_or_default();
      if(check_timetamp_age(message.timestamp,message.symbol) && message.timestamp > current.data.timestamp){
        zrx new_price;
        new_price.data.price = message.price;
        new_price.data.timestamp = message.timestamp;
        singleton.set(new_price, _self);
      }
    } else if(message.symbol == "BAT") {
      bat_t singleton(_self, _self.value);
      bat current = singleton.get_or_default();
      if(check_timetamp_age(message.timestamp,message.symbol) && message.timestamp > current.data.timestamp){
        bat new_price;
        new_price.data.price = message.price;
        new_price.data.timestamp = message.timestamp;
        singleton.set(new_price, _self);
      }
    } else if(message.symbol == "KNC") {
      knc_t singleton(_self, _self.value);
      knc current = singleton.get_or_default();
      if(check_timetamp_age(message.timestamp,message.symbol) && message.timestamp > current.data.timestamp){
        knc new_price;
        new_price.data.price = message.price;
        new_price.data.timestamp = message.timestamp;
        singleton.set(new_price, _self);
      }
    } else if(message.symbol == "LINK") {
      link_t singleton(_self, _self.value);
      link current = singleton.get_or_default();
      if(check_timetamp_age(message.timestamp,message.symbol) && message.timestamp > current.data.timestamp){
        link new_price;
        new_price.data.price = message.price;
        new_price.data.timestamp = message.timestamp;
        singleton.set(new_price, _self);
      }
    } else if(message.symbol == "COMP") {
      comp_t singleton(_self, _self.value);
      comp current = singleton.get_or_default();
      if(check_timetamp_age(message.timestamp,message.symbol) && message.timestamp > current.data.timestamp){
        comp new_price;
        new_price.data.price = message.price;
        new_price.data.timestamp = message.timestamp;
        singleton.set(new_price, _self);
      }
    } else if(message.symbol == "UNI") {
      uni_t singleton(_self, _self.value);
      uni current = singleton.get_or_default();
      if(check_timetamp_age(message.timestamp,message.symbol) && message.timestamp > current.data.timestamp){
        uni new_price;
        new_price.data.price = message.price;
        new_price.data.timestamp = message.timestamp;
        singleton.set(new_price, _self);
      }
    } else if(message.symbol == "GRT") {
      grt_t singleton(_self, _self.value);
      grt current = singleton.get_or_default();
      if(check_timetamp_age(message.timestamp,message.symbol) && message.timestamp > current.data.timestamp){
        grt new_price;
        new_price.data.price = message.price;
        new_price.data.timestamp = message.timestamp;
        singleton.set(new_price, _self);
      }
    } else if(message.symbol == "SNX") {
      snx_t singleton(_self, _self.value);
      snx current = singleton.get_or_default();
      if(check_timetamp_age(message.timestamp,message.symbol) && message.timestamp > current.data.timestamp){
        snx new_price;
        new_price.data.price = message.price;
        new_price.data.timestamp = message.timestamp;
        singleton.set(new_price, _self);
      }
    } 
  }

  message_t unpack(string hex) {
    message_t unpacked_message;

    string type = hex_to_string(clean_zeros(hex.substr(320,64),true));
    uint64_t timestamp = hex_to_uint(clean_zeros(hex.substr(64,64),false));
    string symbol = hex_to_string(clean_zeros(hex.substr(448,64),true));
    uint64_t price = hex_to_uint(clean_zeros(hex.substr(192,64),false));

    check(type == api_type, "wrong type");

    /* add sanity checks on timestamp / price to ensure not insanely large */

    unpacked_message.type = type;
    unpacked_message.timestamp = timestamp;
    unpacked_message.symbol = symbol;
    unpacked_message.price = price;

    return unpacked_message;
  }

  void validate_signature(checksum256 digest, string signature) {
    const bytes& sig = h2bin(signature);
    const bytes& dig = h2bin(hex_to_string(digest));
    bytes ret(65);

    int32_t recovered_uncompressed = k1_recover(
      sig.data(),
      sig.size(),
      dig.data(),
      dig.size(),
      (char*)ret.data(), 
      ret.size()
    );
    
    check(recovered_uncompressed == 0, "failed recover uncompressed");
    check(to_hex(ret.data(),ret.size()) == uncompressed_key, "key mismatch");
  }

  bytes h2bin(const string& source) {
    bytes output(source.length()/2);
    from_hex(source, output.data(), output.size());
    return output;
  }

  string to_hex( const char* d, uint32_t s ) {
    string r;
    const char* to_hex="0123456789abcdef";
    uint8_t* c = (uint8_t*)d;
    for( uint32_t i = 0; i < s; ++i )
        (r += to_hex[(c[i]>>4)]) += to_hex[(c[i] &0x0f)];
    return r;
  }

  uint8_t from_hex( char c ) {
    if( c >= '0' && c <= '9' )
      return c - '0';
    if( c >= 'a' && c <= 'f' )
        return c - 'a' + 10;
    if( c >= 'A' && c <= 'F' )
        return c - 'A' + 10;
    return 0;
  }

  size_t from_hex( const string& hex_str, char* out_data, size_t out_data_len ) {
    auto i = hex_str.begin();
    uint8_t* out_pos = (uint8_t*)out_data;
    uint8_t* out_end = out_pos + out_data_len;
    while( i != hex_str.end() && out_end != out_pos ) {
      *out_pos = from_hex( *i ) << 4;   
      ++i;
      if( i != hex_str.end() )  {
          *out_pos |= from_hex( *i );
          ++i;
      }
      ++out_pos;
    }
    return out_pos - (uint8_t*)out_data;
  }

  
  static string hex_to_string(const checksum256 &hashed) {
		string result;
		const char *hex_chars = "0123456789abcdef";
		const auto bytes = hashed.extract_as_byte_array();

		for (uint32_t i = 0; i < bytes.size(); ++i) {
			(result += hex_chars[(bytes.at(i) >> 4)]) += hex_chars[(bytes.at(i) & 0x0f)];
		}

		return result;
	}
  
  static string hex_to_string(const string &hex) {
		string result;
    int len = hex.length();
    string new_string;

    for(int i=0; i< len; i+=2) {
      std::string byte = hex.substr(i,2);
      char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
      new_string.push_back(chr);
    }

		return new_string;
	}
  
  static uint64_t hex_to_uint(string hex) {
    return strtoull(hex.c_str(), NULL, 16);
	}

  static string clean_zeros(const string &hex, bool trailing) {
    if(trailing) {
      size_t found = hex.find_last_not_of('0');
      string new_str = hex.substr(0,found+1);
      if(new_str.size() % 2) new_str = new_str + '0';
      return new_str;
    } else {
      size_t found = hex.find_first_not_of('0');
      string new_str = hex.substr(found,hex.size() - found);
      if(new_str.size() % 2) new_str = '0' + new_str;
      return new_str;
    }
  }

  // converts hex to bytes array and sha3 hashes
  static checksum256 hash(const string& hex) {
    char chars[hex.length() / 2];

    for (int i = 0; i < hex.length(); i += 2) {
      chars[i/2] = (char) strtol(hex.substr(i, 2).c_str(), NULL, 16);
    }

    return keccak(chars,sizeof(chars));
  }

  struct data_t {
    uint64_t timestamp;
    uint64_t price;
  };

  TABLE btc {
    data_t data;
  };
  typedef singleton<"btc"_n, btc> btc_t;

  TABLE eth {
    data_t data;
  };
  typedef singleton<"eth"_n, eth> eth_t;

  TABLE xtz {
    data_t data;
  };
  typedef singleton<"xtz"_n, xtz> xtz_t;

  TABLE dai {
    data_t data;
  };
  typedef singleton<"dai"_n, dai> dai_t;

  TABLE rep {
    data_t data;
  };
  typedef singleton<"rep"_n, rep> rep_t;

  TABLE zrx {
    data_t data;
  };
  typedef singleton<"zrx"_n, zrx> zrx_t;

  TABLE bat {
    data_t data;
  };
  typedef singleton<"bat"_n, bat> bat_t;

  TABLE knc {
    data_t data;
  };
  typedef singleton<"knc"_n, knc> knc_t;

  TABLE link {
    data_t data;
  };
  typedef singleton<"link"_n, link> link_t;

  TABLE comp {
    data_t data;
  };
  typedef singleton<"comp"_n, comp> comp_t;

  TABLE uni {
    data_t data;
  };
  typedef singleton<"uni"_n, uni> uni_t;

  TABLE grt {
    data_t data;
  };
  typedef singleton<"grt"_n, grt> grt_t;

  TABLE snx {
    data_t data;
  };
  typedef singleton<"snx"_n, snx> snx_t;
};