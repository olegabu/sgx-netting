//
// Created by vytautas on 9/13/17.
//

#include <csignal>

#include <pistache/http.h>
#include <pistache/router.h>
#include <pistache/endpoint.h>
#include "json.hpp"

#include <pistache/http.h>
#include <pistache/router.h>
#include <pistache/endpoint.h>
#include "json.hpp"

#include "serial_trades.h"
#include "util.h"
#include "app.h"

#include "iostream"

#include "NotionalMatrix.h"

#include "SemiLocalAlgorithm.h"
#include "crypto.h"
#include "enclave_u.h"

#include "base64.h"

using namespace std;
using namespace Pistache;
using json = nlohmann::json;

template<class T>
inline json& operator<<(json& j, const T& t){
    j.push_back(t);
    return j;
}

class Endpoint {
public:
    Endpoint(Address addr)
            : httpEndpoint(std::make_shared<Http::Endpoint>(addr))
    { }

    void init(size_t thr = 2) {
        auto opts = Http::Endpoint::options()
                .threads(thr)
                //.flags(Tcp::Options::InstallSignalHandler)
                .flags(Tcp::Options::ReuseAddr);
        httpEndpoint->init(opts);
        setupRoutes();
    }

    void start() {
        httpEndpoint->setHandler(router.handler());
        httpEndpoint->serveThreaded();
    }

    void shutdown() {
        httpEndpoint->shutdown();
    }

private:
    void setupRoutes() {
        using namespace Rest;

        Routes::Get(router, "/sgx_available",
                    Routes::bind(&Endpoint::sgx_available, this));

        Routes::Get(router, "/ec256_gen_key",
                    Routes::bind(&Endpoint::do_ec256_gen_key, this));
        Routes::Post(router, "/trades/encrypt",
                     Routes::bind(&Endpoint::do_trades_encrypt, this));
        Routes::Post(router, "/trades/decrypt",
                     Routes::bind(&Endpoint::do_trades_decrypt, this));
        Routes::Post(router, "/compress",
                     Routes::bind(&Endpoint::do_compress, this));

    }

    void sgx_available(const Rest::Request& request, Http::ResponseWriter response){
        response.send(Http::Code::Ok, "true", MIME(Application, Json)); // FIXME: assumes enclave init is a good enough test
    }

    void do_ec256_gen_key(const Rest::Request& request, Http::ResponseWriter response){
        sgx_ec256_private_t prv_key = {0};
        sgx_ec256_public_t  pub_key = {0};
        ec256_gen_key(&prv_key, &pub_key);

        to_ec_key(&prv_key);

        buffer buf;
        buf.write(&prv_key, 32);
        buf.write(&pub_key, 64);
        response.send(Http::Code::Ok, base64_encode(string((char*)buf.data(),buf.size())), MIME(Application, Star));
    }

    void do_trades_encrypt(const Rest::Request& request, Http::ResponseWriter response){

        sgx_ec256_private_t prv_key = {0};
        sgx_ec256_public_t  pub_key = {0};

        json j = json::parse(request.body());
        string key_b64 = j["key"].get<string>();
        string key_bin = base64_decode(key_b64);
        memcpy(&prv_key, key_bin.data(), 32);
        memcpy(&pub_key, key_bin.data()+32, 64);

        assert(ec256_check_point(&pub_key));
        vector<ClearedTrade> trades;
        map<string, shared_ptr<StandardId>> ps_to_p;

        json j_trades = j["trades"];
        string party = j["party"];

        assert(j_trades.is_array());
        // walk through and fill the vector
        for(int i=0;i<j_trades.size();i++) {
            json j_trade = j_trades[i];

            json party_a = j_trade[0];
            json party_b = j_trade[1];
            int64_t value = j_trade[2];

            party_id_t p_a = party_a.get<string>();
            party_id_t p_b = party_b.get<string>();

            ClearedTrade t;
            t.party = p_a;
            t.counter_party = p_b;
            t.value = value;

            trades.push_back(t);
        }

        buffer trade_data;
        trade_data << party;
        write_trades(trades, trade_data);

        sgx_status_t sret, ret;
        sgx_ec256_public_t e_pub_key;

        sret = e_get_pub_key(G.enclave_id, &ret, &e_pub_key);
        assert(ec256_check_point(&e_pub_key));
        if(sret != SGX_SUCCESS || ret != SGX_SUCCESS) {
            printf("\nError at %d, %d, %d." , __LINE__, sret, (int32_t)ret);
        }

        ec256_dhkey_t secret = get_shared_dhkey(&prv_key, &e_pub_key);

        AES_GCM_msg msg = ec256_encrypt_msg(&pub_key, &secret, trade_data);

        buffer msg_buf;
        msg_buf << msg;

        string b64_in((const char*)msg_buf.data(), msg_buf.size());
        string out = base64_encode(b64_in);
        response.send(Http::Code::Ok, string((char*)out.data(), out.size()), MIME(Application, Star));
    }

    void do_trades_decrypt(const Rest::Request& request, Http::ResponseWriter response){
        string in = base64_decode(request.body());
        buffer msg_buf;
        msg_buf.write(in.data(), in.size());

        sgx_ec256_private_t prv_key = {0};

        msg_buf.read(&prv_key, 32);
        msg_buf.read(0, 64);

        AES_GCM_msg msg;
        msg_buf >> msg;

        buffer out = ec256_decrypt_msg(&prv_key, msg);

        string party;
        out >> party;

        vector<ClearedTrade> trades = read_trades(out.read_ptr(), out.size());

        json j;
        json j_trades = json::array();

        for(ClearedTrade& t : trades){
            json j_t = json::array();

            j_t << t.party << t.counter_party << t.value;

            j_trades << j_t;
        }

        j["party"] = party;
        j["trades"] = j_trades;

        response.send(Http::Code::Ok, j.dump(2), MIME(Application, Star));
    }

    void do_compress(const Rest::Request& request, Http::ResponseWriter response) {
        json j = json::parse(request.body());

        json j_inputs = j["inputs"];

        assert(j_inputs.is_array());
        vector<string> inputs;
        for (int i = 0; i < j_inputs.size(); i++) {
            inputs.push_back(base64_decode(j_inputs[i]));
        }

        buffer buf;
        buf.put_i4(inputs.size());
        for (int i = 0; i < inputs.size(); i++){
            buf.write(inputs[i].data(), inputs[i].size());
        }
        uint8_t *out;
        uint32_t out_size;
        {
            sgx_status_t ret, sret;
            ret = compress_slv1_vector(
                    G.enclave_id, &sret,
                    buf.data(), buf.size(), &out, &out_size);
        }
        vector<string> parties;
        vector<AES_GCM_msg> datas;

        buf = buffer();
        buf.write(out, out_size);

        buf >> parties;
        buf >> datas;

        json ret;
        json j_p = json::array();
        for(string& p : parties)
            j_p.push_back(p);
        ret["parties"] = j_p;

        json j_o = json::array();
        for(AES_GCM_msg& msg : datas){
            buffer msg_buf;
            msg_buf << msg;

            j_o.push_back(base64_encode(string((char*)msg_buf.data(), msg_buf.size())));
        }
        ret["outputs"] = j_o;

        response.send(Http::Code::Ok, ret.dump(2), MIME(Application, Star));
    }

    std::shared_ptr<Http::Endpoint> httpEndpoint;
    Rest::Router router;
};

Endpoint* server;
bool running = 1;

void interrupt(int signal)
{
    cerr << "Interrupted, exiting...\n" << endl;
    running = 0;
}

int main(int argc, char* argv[])
{
    bool enclave_changed = false;
    app_init(enclave_changed);

    printf("Enclave changed: %d\n", enclave_changed);

    signal(SIGINT, interrupt);
    signal(SIGTERM, interrupt);

    Port port(8080);

    int thr = 1;

    if (argc >= 2) {
        port = std::stol(argv[1]);

        if (argc == 3)
            thr = std::stol(argv[2]);
    }

    Address addr(Ipv4::any(), port);

    cout << "Cores = " << hardware_concurrency() << endl;
    cout << "Using " << thr << " threads" << endl;

    server = new Endpoint(addr);
    Endpoint& serv = *server;

    serv.init(thr);
    serv.start();

    while(running)
        sleep(1);

    serv.shutdown();

    app_close();
    return 0;
}
