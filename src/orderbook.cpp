//not considering time

#include <map>
#include <cstdio>
#include <string>
#include <assert.h>

using namespace std;

const int BUY = 1;
const int SELL = -1;

struct Order {
    int id;
    int user;
    double price; //sell: price > 0; buy: price < 0
    double volume;

    Order() {
        id = user = 0;
        price = volume = 0;
    }

    Order(int id, int user, double price, double volume) : 
        id(id), user(user), price(price), volume(volume) {}

	void output() {
		printf("order_id: %d; user_id: %d; price: %f; volume: %f\n", id, user, price, volume);
	}

};

struct Orderbook {
	map<pair<double, int>, Order> book; //map<pair<price, order_id>, order>

	Orderbook() {
		book.clear();
	}	

	double erase(pair<double, int> idx) {
		assert(book.find(idx) != book.end());
		double volume = book[idx].volume;
		book.erase(idx);
		return volume;
	}

	void insert(int user, int id, double price, double volume) {
		book[pair<double, int>(price, id)] = Order(id, user, price, volume);
	}

	bool empty() {
		return book.empty();
	}

	double begin_price() {
		return book.begin()->first.first;
	}

	Order pop() {
		Order result = book.begin()->second;
		book.erase(pair<double, int>(result.price, result.id));
		return result;
	}

} sell_order, buy_order;

map<int, map<int, double> > users; //map<user_id, map<order_id, price> >

struct Tx {
    int id;
    int seller, buyer;
    int sell_order, buy_order;
    double sell_price, buy_price;
    double volume;

    Tx() {
        id = seller = buyer = sell_order = buy_order = 0;
        sell_price = buy_price = volume = 0;
    }

    Tx(int id, int seller, int buyer, int sell_order, int buy_order, double sell_price, double buy_price, double volume) :
        id(id), seller(seller), buyer(buyer), sell_order(sell_order), buy_order(buy_order), 
		sell_price(sell_price), buy_price(buy_price), volume(volume) {}

	void output() {
		printf("tx_id: %d; seller: %d, (order_id: %d, price: %f); buyer: %d, (order_id: %d, price: %f); volume: %f\n", 
				id, seller, sell_order, sell_price, buyer, buy_order, buy_price, volume);
	}

};

map<int, map<int, Tx> > txs; //map<user_id, map<tx_id, tx> >

int main() {
//    freopen("test.in", "r", stdin);
    int n, m;
    scanf("%d %d", &n, &m); //get user# and commands#

    int tot_order = 0, tot_tx = 0; //initiation
    users.clear();
    txs.clear();

    for (int o = 0; o < m; ++o) {
        char st[100];
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

				if (price > 0) {
					volume = sell_order.erase(pair<double, int>(price, id));
				} else {
					volume = buy_order.erase(pair<double, int>(price, id));
				}

                txs[user][tot_tx] = Tx(tot_tx, user, user, id, id, price, price, volume);
                ++tot_tx;

                users[user].erase(id);
				if (users[user].empty()) users.erase(user);
            } else {
				printf("Order not found!");
			}
        } else if (string(st) == "BUY" || string(st) == "SELL") { //(user_id, BUY/SELL, price, volume)
            scanf("%lf %lf", &price, &volume);
            
            if (string(st) == "BUY") {
				price = -price;
                buy_order.insert(user, tot_order, price, volume);
            } else if (string(st) == "SELL") {
                sell_order.insert(user, tot_order, price, volume);
            }

            users[user][tot_order] = price;
            ++tot_order;
        } else if (string(st) == "CHECK") {
			printf("Orders:\n");
			if (users.find(user) != users.end()) {
				for (map<int, double>::iterator it = users[user].begin(); it != users[user].end(); ++it) {
					if (it->second > 0) {
						sell_order.book[pair<double, int>(it->second, it->first)].output();
					} else {
						buy_order.book[pair<double, int>(it->second, it->first)].output();
					}
				}
			} else {
				printf("No order found.\n");
			}	
			printf("\n");

			printf("Transactions:\n");
			if (txs.find(user) != txs.end()) {
				for (map<int, Tx>::iterator it = txs[user].begin(); it != txs[user].end(); ++it) {
					it->second.output();
				}
			} else {
				printf("No transaction found.\n");
			}
			printf("\n");
		}

        while (!buy_order.empty() && !sell_order.empty() 
                && (-buy_order.begin_price()) >= sell_order.begin_price()) {
			Order buy = buy_order.pop();
			Order sell = sell_order.pop();
			
            double vol = min(buy.volume, sell.volume);

			if (buy.volume > vol) {
				buy_order.insert(buy.user, buy.id, buy.price, buy.volume - vol);
			} else {
				users[buy.user].erase(buy.id);
				if (users[buy.user].empty()) users.erase(buy.user);
			}
			txs[buy.user][tot_tx] = Tx(tot_tx, sell.user, buy.user, sell.id, buy.id, sell.price, -buy.price, vol);

			if (sell.volume > vol) {
				sell_order.insert(sell.user, sell.id, sell.price, sell.volume - vol);
			} else {
				users[sell.user].erase(sell.id);
				if (users[sell.user].empty()) users.erase(sell.user);
			}
			txs[sell.user][tot_tx] = Tx(tot_tx, sell.user, buy.user, sell.id, buy.id, sell.price, -buy.price, vol);

			++tot_tx;
        }

    }
//    fclose(stdin);
    return 0; 
}

