//
// Created by vytautas on 10/3/17.
//

#include <pistache/client.h>
#include <pistache/async.h>
#include "json.hpp"
#include <signal.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>
#include <string>
#include <sstream>

using namespace std;

#define READ   0
#define WRITE  1
FILE * popen2(string command, string type, int & pid)
{
    pid_t child_pid;
    int fd[2];
    pipe(fd);

    if((child_pid = fork()) == -1)
    {
        perror("fork");
        exit(1);
    }

    /* child process */
    if (child_pid == 0)
    {
        if (type == "r")
        {
            close(fd[READ]);    //Close the READ end of the pipe since the child's fd is write-only
            dup2(fd[WRITE], 1); //Redirect stdout to pipe
        }
        else
        {
            close(fd[WRITE]);    //Close the WRITE end of the pipe since the child's fd is read-only
            dup2(fd[READ], 0);   //Redirect stdin to pipe
        }

        setpgid(child_pid, child_pid); //Needed so negative PIDs can kill children of /bin/sh
        execl("/bin/sh", "/bin/sh", "-c", command.c_str(), NULL);
        exit(0);
    }
    else
    {
        if (type == "r")
        {
            close(fd[WRITE]); //Close the WRITE end of the pipe since parent's fd is read-only
        }
        else
        {
            close(fd[READ]); //Close the READ end of the pipe since parent's fd is write-only
        }
    }

    pid = child_pid;

    if (type == "r")
    {
        return fdopen(fd[READ], "r");
    }

    return fdopen(fd[WRITE], "w");
}

int pclose2(FILE * fp, pid_t pid)
{
    int stat;

    fclose(fp);
    while (waitpid(pid, &stat, 0) == -1)
    {
        if (errno != EINTR)
        {
            stat = -1;
            break;
        }
    }

    return stat;
}

using namespace std;
using namespace Pistache;
using namespace Pistache::Http;
using json = nlohmann::json;

#define WAIT(X) \
    Async::Barrier<Response> barrier(X); \
    barrier.wait();

string http_base = "http://127.0.0.1:8080/";

inline string encrypt(Client& http, string data)
{
    auto req = http.post(http_base+"/trades/encrypt");

    req.body(data);

    auto p_resp = req.send();

    string output;
    p_resp.then([&](Response resp){
        cout << "Input:\n" << resp.body() << endl;
        output = resp.body();
    }, Async::IgnoreException);

    WAIT(p_resp);

    return output;
}
inline string decrypt(Client& http, string key, string output)
{
    auto req = http.post(http_base+"/trades/decrypt");

    req.body(key + output);

    auto p_resp = req.send();

    string ret;
    p_resp.then([&](Response resp){
        json j = json::parse(resp.body());
        cout << "Decrypted output for party " + j["party"].get<string>() << ":\n";

        cout << resp.body() << endl;

        ret = resp.body();

    }, Async::IgnoreException);

    WAIT(p_resp);

    return ret;
}

int main(int argc, char** argv)
{
    // Start server

    int server_pid;
    FILE* server = popen2("./rest_sgx", "r+b", server_pid);

    sleep(2);

    // Test Rest routes
    Client http;

    http.init(http.options());

    map<string, string> keys_map;
    vector<string> keys(2);

    vector<string> inputs(2);

    // Generate key
    for(int i=0;i<2;i++){
        auto p_resp = http.get(http_base+"/ec256_gen_key").send();

        p_resp.then([&](Response resp){
            keys[i] = resp.body();
        }, Async::IgnoreException);

        WAIT(p_resp);

        assert(keys[i].size() == 128);
    }

    keys_map["a~a"] = keys[0];
    keys_map["a~b"] = keys[1];

    // Encrypt trades
    inputs[0] = encrypt(http, R"({
 "party" : "a~a",
 "key" : ")" + keys[0] + R"(",
 "trades": [
	["a~a", "a~b", 3],
	["a~a", "a~c", -3]
 ]
})");
    inputs[1] = encrypt(http, R"({
 "party" : "a~b",
 "key" : ")" + keys[1] + R"(",
 "trades": [
	["a~b", "a~a", -3],
	["a~b", "a~c", 3]
 ]
})");

    string compress_response;
    // Compress trades
    {
        json j;
        json j_a = json::array();

        for(int i=0;i<2;i++)
            j_a.push_back(inputs[i]);

        j["inputs"] = j_a;


        auto req = http.post(http_base+"/compress");
        req.body( j.dump(2) );

        auto p_resp = req.send();

        p_resp.then([&](Response resp){
            compress_response = resp.body();
        }, Async::IgnoreException);

        WAIT(p_resp);
    }

    // Decrypt output trades
    {
        json j = json::parse(compress_response);

        json j_parties = j["parties"];
        for (int i = 0; i < j_parties.size(); i++) {
            string party = j_parties[i];
            string output = j["outputs"][i];

            string data = decrypt(http, keys_map[party], output);
        }
    }

    http.shutdown();

    kill(server_pid, SIGINT);
    pclose2(server, server_pid);
    return 0;
}