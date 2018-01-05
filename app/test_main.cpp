//
// Created by vytautas on 9/13/17.
//

#include "serial_trades.h"
#include "util.h"
#include "app.h"

#include "iostream"

#include "NotionalMatrix.h"

#include "SemiLocalAlgorithm.h"

using namespace std;
int main(int argc, char* argv[])
{
    bool enclave_changed = false;
    app_init(enclave_changed);

    vector<ClearedTrade> trades = load_trades();

    NotionalMatrix mat;
    mat.add(trades);
    printf("--- Input trades.txt ---\n");
    printf("n_trades: %d %d\n", trades.size(), mat.n_trade_pairs());
    cout << trades << endl;

    SemiLocalAlgorithm algo;
    NotionalMatrix newmat = algo.compress(mat);

    cout << "--- New notional matrix --- " << endl;
    cout << newmat << endl;
    buffer buf;
    write_trades(trades, buf);

    printf("Serialized trade data:\n");
    print_raw(buf.data(), buf.size());

    printf("\n--- EC256 CODE ---\n");
    algo_ec256(G.enclave_id, buf);
}
