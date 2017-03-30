//not considering time

#include <map>
#include <cstdio>
#include <string>

using namespace std;

enum order_type {BUY, SELL};

struct Order {
    int id;
    int user;
    double price;
    double volume;
    order_type type;

    Order() {
        id = user = 0;
        price = volume = 0;
    }

    Order(int id, int user, double price, double volume, order_type type) : 
        id(id), user(user), price(price), volume(volume), type(type) {}

};

map<int, map<int, double> > users; //map<user_id, map<order_id, price> >
map<pair<double, int>, Order> sell_order, buy_order; //map<pair<price, order_id>, order>

struct Tx {
    int id;
    int seller, buyer;
    int sell_order, buy_order;
    double price;
    double volume;

    Tx() {
        id = seller = buyer = sell_order = buy_order = 0;
        price = volume = 0;
    }

    Tx(int id, int seller, int buyer, int sell_order, int buy_order, double price, double volume) :
        id(id), seller(seller), buyer(buyer), sell_order(sell_order), 
        buy_order(buy_order), price(price), volume(volume) {}

};

map<int, map<int, Tx> > txs; //map<user_id, map<tx_id, tx> >

int main() {
    freopen("test.in", "r", stdin);
    int n, m;
    scanf("%d %d", &n, &m); //get user# and commands#


    int tot_order = 0, tot_tx = 0; //initiation
    users.clear();
    sell_order.clear();
    buy_order.clear();
    txs.clear();

    for (int o = 0; o < m; ++o) {
        char st[10];
        int user;
        double price, volume;
        scanf("%d %s", &user, st);
        
        //insert the new order into the orderbook
        if (string(st) == "CANCEL") { //(user_id, CANCEL, order_id)
            int id;
            scanf("%d", &id);
            if (users.find(user) != users.end() 
                    && users[user].find(id) != users[user].end()) {
                price = users[user][id];

                if (buy_order.find(pair<double, int>(price, id)) != buy_order.end()) {
                    volume = buy_order[pair<double, int>(price, id)].volume;
                    buy_order.erase(pair<double, int>(price, id));
                }
                if (sell_order.find(pair<double, int>(price, id)) != sell_order.end()) {
                    volume = sell_order[pair<double, int>(price, id)].volume;
                    sell_order.erase(pair<double, int>(price, id));
                }

                txs[user][tot_tx] = Tx(tot_tx, user, user, id, id, price, volume);
                ++tot_tx;

                users[user].erase(id);
            }
        } else { //(user_id, BUY/SELL, price, volume)
            scanf("%lf %lf", &price, &volume);
            
            users[user][tot_order] = price;
            
            if (string(st) == "BUY") {
                buy_order[pair<double, int>(price, tot_order)] = Order(tot_order, user, price, volume, BUY);
            } else if (string(st) == "SELL") {
                sell_order[pair<double, int>(price, tot_order)] = Order(tot_order, user, price, volume, SELL);
            }
            ++tot_order;
        }

        //TODO: start to match orders and form txs
        while (!buy_order.empty() && !sell_order.empty() 
                && buy_order.rbegin()->first.first >= sell_order.begin()->first.first) {
            double val = min(buy_order.rbegin()->second.volume, sell_order.begin()->second.volume);
            double pri = buy_order.rbegin()->first.first;
            if (val < buy_order.rbegin()->second.volume) {
            } else {
            }
            if (val < sell_order.begin()->second.volume) {
            } else {
            }
        }

    }
    fclose(stdin);
    return 0; 
}

