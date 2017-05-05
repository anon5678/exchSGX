//transaction fee: settled orders
//price * volume might overflow

#include <map>
#include <cstdio>
#include <string>
#include <assert.h>

#include<ctime>

#define ULL unsigned long long

using namespace std;

const int SELL = 1;
const int BUY = 0;
const string TYPE[2] = {"BUY", "SELL"};

const int TX_TIMEOUT = -1;
const int TX_CANCEL = -2;

//currencies
const int COIN_NUM = 3;
const int PAIR_NUM = 3;
const string COIN[COIN_NUM] = {"BTC", "LTC", "ETH"};
const string EXCHANGE[PAIR_NUM] = {"LTC/BTC", "ETH/BTC", "LTC/ETH"};
const int COINREF[PAIR_NUM][2] = {1, 0,
								  2, 0,
								  1, 2};

//valid operation periods
const long DAY = 1;//24 * 60 * 60;
const long DEPOSIT_PERIOD = 30 * DAY;
const long WITHDRAW_PERIOD = 5 * DAY;
const long RENEW_PERIOD = 15 * DAY;
const long ORDER_PERIOD = 5 * DAY;
const long CANCEL_PERIOD = 5 * DAY;

//transaction fees
const ULL WITHDRAW_FEE[COIN_NUM] = {0, 0, 0};
const ULL RENEW_FEE[COIN_NUM] = {0, 0, 0};
const ULL SETTLE_FEE[PAIR_NUM][2] = {0, 0,
									 0, 0,
									 0, 0};

long tot_order = 0, tot_tx = 0; //initiation

inline long getTime() {
	time_t current_time = time(nullptr);
	printf("%s%ld\n", asctime(localtime(&current_time)), current_time);
	return current_time;
}

struct Deposit {
	long timeout;
	ULL volume, left;

	Deposit() {
		volume = left = 0;
		timeout = 0;
	}

	Deposit(ULL volume, ULL left, long timeout) :
		volume(volume), left(left), timeout(timeout) {}
	
	void output() {
		printf("volume: %lld; left: %lld; timeout: %ld\n", 
				volume, left, timeout);
	}

};

struct Order {
	int type;
    ULL price;
    ULL volume;
	long timestamp;

    Order() {
        price = 0;
		volume = 0;
		timestamp = 0;
    }

    Order(int type, ULL price, ULL volume, long timestamp) : 
        type(type), price(price), volume(volume), timestamp(timestamp) {}

	void output() {
		printf("type: %s; price: %lld; volume: %lld; timestamp: %ld\n", 
				TYPE[type].c_str(), price, volume, timestamp);
	}

};

struct Tx {
    long trader_id, order_id;
	int type;
    ULL volume;
	ULL price;
	long timestamp;

    Tx() {
        trader_id = order_id = 0;
		price = 0;
        volume = 0;
		timestamp = 0;
    }

    Tx(long trader_id, long order_id, int type, ULL price, ULL volume, long timestamp) :
		trader_id(trader_id), order_id(order_id), type(type),
		price(price), volume(volume), timestamp(timestamp) {}

	void output() {
		if (trader_id == TX_TIMEOUT) {
			printf("TIMEOUT; ");
		} else if (trader_id == TX_CANCEL) {
			printf("CANCELLED; ");
		} else {
			printf("trader_id: %ld; ", trader_id);
		}
		printf("order_id: %ld; type: %s; price: %lld; volume: %lld; timestamp: %ld\n", 
				order_id, TYPE[type].c_str(), price, volume, timestamp);
	}

};


//map<pair<price, order_id>, user_id> [pair_num]
struct Orderbook {
	map<pair<ULL, long>, long> sell_book, buy_book; 
	
	Orderbook() {
		sell_book.clear();
		buy_book.clear();
	}

	void insert(int type, ULL price, long order_id, long user_id) {
		if (type == BUY) {
			buy_book[make_pair(price, order_id)] = user_id;
		} else {
			sell_book[make_pair(price, order_id)] = user_id;
		}
	}

	void erase(int type, ULL price, long order_id) {
		if (type == BUY) {
			buy_book.erase(make_pair(price, order_id));
		} else {
			sell_book.erase(make_pair(price, order_id));
		}
	}

	bool settle() {
		return !sell_book.empty() && !buy_book.empty()
			&& sell_book.begin()->first.first <= buy_book.rbegin()->first.first;
	}

} orderbook[PAIR_NUM];


//map<user_id, deposit> [coin_num]
struct UserDeposit {
	map<long, Deposit> book;

	UserDeposit() {
		book.clear();
	}

	long deposit(long timestamp, long user_id, ULL volume) {
		timestamp += DEPOSIT_PERIOD;
		if (book.find(user_id) == book.end()) {
			book[user_id] = Deposit(volume, volume, timestamp);
		} else {
			book[user_id].volume += volume;
			book[user_id].left += volume;
		}
		return book[user_id].timeout;
	}

	ULL withdraw(long timestamp, long user_id, ULL volume, ULL fee) {
		if (book.find(user_id) == book.end()
				|| timestamp + WITHDRAW_PERIOD > book[user_id].timeout
				|| book[user_id].left < fee) {
			return 0;
		} else {
			book[user_id].volume -= fee;
			book[user_id].left -= fee;

			volume = min(volume, book[user_id].left);
			book[user_id].volume -= volume;
			book[user_id].left -= volume;
			if (book[user_id].volume == 0) {
				book.erase(user_id);
			}
			return volume;
		}
	}

	long renew(long timestamp, long user_id, ULL fee) {
		if (book.find(user_id) == book.end()
				|| timestamp + RENEW_PERIOD > book[user_id].timeout
				|| book[user_id].left < fee) {
			return -1;
		} else {
			book[user_id].volume -= fee;
			book[user_id].left -= fee;

			timestamp = max(book[user_id].timeout, timestamp + DEPOSIT_PERIOD);
			book[user_id].timeout = timestamp;
			return timestamp;
		}
	}

	bool order(long timestamp, long user_id, ULL volume) {
		if (book.find(user_id) == book.end()
				|| timestamp + ORDER_PERIOD > book[user_id].timeout
				|| book[user_id].left < volume) {
			return false;
		} else {
			book[user_id].left -= volume;
			return true;
		}
	}

	bool cancel(long timestamp, long user_id, ULL volume) {
		if (book.find(user_id) == book.end()
				|| timestamp + CANCEL_PERIOD > book[user_id].timeout) {
			return false;
		} else {
			book[user_id].left += volume;
			return true;
		}
	}

	void settle(long user_id, ULL volume) {
		book[user_id].volume -= volume;
	}

	bool find(long user_id) {
		return book.find(user_id) != book.end();
	}

	void erase(long user_id) {
		book.erase(user_id);
	}

} deposits[COIN_NUM];


//map<user_id, map<order_id, order> > [pair_num]
struct UserOrder {
	map<long, map<long, Order> > book;

	UserOrder() {
		book.clear();
	}

	void insert(long user_id, long order_id, Order order) {
		book[user_id][order_id] = order;
	}

	void erase(long user_id, long order_id) {
		book[user_id].erase(order_id);
		if (book[user_id].empty()) {
			book.erase(user_id);
		}
	}

	Order getOrder(long user_id, long order_id) {
		return book[user_id][order_id];
	}

	void settle(long user_id, long order_id, ULL volume) {
		book[user_id][order_id].volume -= volume;
	}

	bool find(long user_id) {
		return book.find(user_id) != book.end();
	}

	bool find(long user_id, long order_id) {
		return book.find(user_id) != book.end()
			&& book[user_id].find(order_id) != book[user_id].end();
	}

} orders[PAIR_NUM];

//map<user_id, map<tx_id, tx> > [pair_num]
struct UserTx {
	map<long, map<long, Tx> > book;

	UserTx() {
		book.clear();
	}

	void insert(long user_id, long tx_id, Tx tx) {
		book[user_id][tx_id] = tx;
	}

	bool find(long user_id) {
		return book.find(user_id) != book.end();
	}

} txs[PAIR_NUM];

bool expiration_check(long timestamp, long user_id, int coin) {
	if (deposits[coin].find(user_id)
			&& deposits[coin].book[user_id].timeout < timestamp) {
		printf("Deposit for %s timeout!\n", COIN[coin].c_str());
		timestamp = deposits[coin].book[user_id].timeout;

		for (int o = 0; o < PAIR_NUM; ++o) {
			for (int type = 0; type < 2; ++type) {
				if (COINREF[o][type] == coin && orders[o].find(user_id)) {
					for (map<long, Order>::iterator it = orders[o].book[user_id].begin();
							it != orders[o].book[user_id].end();) {
						if (it->second.type == type) {
							long order_id = it->first;
							Order order = it->second;

							orderbook[o].erase(type, order.price, order_id);

							txs[o].insert(user_id, tot_tx, Tx(TX_TIMEOUT, order_id, order.type, order.price, order.volume, timestamp));
							++tot_tx;

							++it;
							orders[o].erase(user_id, order_id);
							if (!orders[o].find(user_id)) break;
						} else {
							++it;
						}
					}
				}
			}
		}

		deposits[coin].erase(user_id);
		return true;
	}
	return false;
}

void deposit() {
	// (DEPOSIT, timestamp, user_id, coin, volume)
	int coin;
	ULL volume;
	long timestamp, user_id;
	scanf("%ld %ld %d %lld", &timestamp, &user_id, &coin, &volume);
	
	expiration_check(timestamp, user_id, coin);

	timestamp = deposits[coin].deposit(timestamp, user_id, volume);
	printf("User %ld successfully deposits %lld %s with timeout %ld.\n", 
			user_id, volume, COIN[coin].c_str(), timestamp);
}

void withdraw() {
	// (WITHDRAW, timestamp, user_id, coin, volume)
	int coin;
	ULL volume;
	long timestamp, user_id;
	scanf("%ld %ld %d %lld", &timestamp, &user_id, &coin, &volume);

	expiration_check(timestamp, user_id, coin);

	volume = deposits[coin].withdraw(timestamp, user_id, volume, WITHDRAW_FEE[coin]);
	printf("User %ld successfully withdraws %lld %s.\n", 
			user_id, volume, COIN[coin].c_str());
}

void renew() {
	// (RENEW, timestamp, user_id, coin)
	int coin;
	long timestamp, user_id;
	scanf("%ld %ld %d", &timestamp, &user_id, &coin);

	expiration_check(timestamp, user_id, coin);

	timestamp = deposits[coin].renew(timestamp, user_id, RENEW_FEE[coin]);
	if (timestamp < 0) {
		printf("Renew fails.");
	} else {
		printf("Deposit successfully renews to %ld.\n", timestamp);
	}
}

void order(int type) {
	// (BUY/SELL, timestamp, user_id, pair, price, volume)
	long timestamp, user_id;
	ULL price;
	int pair;
	ULL volume;
    scanf("%ld %ld %d %lld %lld", &timestamp, &user_id, &pair, &price, &volume);

	expiration_check(timestamp, user_id, COINREF[pair][type]);

	ULL vol = volume;
	if (type == BUY) {
		vol *= price;
	}
	
	if (deposits[COINREF[pair][type]].order(timestamp, user_id, vol)) {
		orderbook[pair].insert(type, price, tot_order, user_id);
	} else {
		printf("Order fails: not enough %s.\n", COIN[COINREF[pair][type]].c_str());
		return;
	}

	orders[pair].insert(user_id, tot_order, Order(type, price, volume, timestamp));
	++tot_order;

	printf("Successfully make order %ld.\n", tot_order - 1);
}

void cancel() {
	// (CANCEL, timestamp, user_id, pair, order_id)
	long timestamp, user_id, order_id;
	int pair;
	scanf("%ld %ld %d %ld", &timestamp, &user_id, &pair, &order_id);

	if (!orders[pair].find(user_id, order_id)) {
		printf("Order not found!\n");
		return;
	}

	bool flag;

	Order order = orders[pair].getOrder(user_id, order_id);
	ULL volume = order.volume;
	if (order.type == BUY) {
		volume *= order.price;
	}
	
	if (expiration_check(timestamp, user_id, COINREF[pair][order.type])) {
		flag = false;
	} else {
		flag = deposits[COINREF[pair][order.type]].cancel(timestamp, user_id, volume);
	}
	
	if (flag) {
		orderbook[pair].erase(order.type, order.price, order_id);
		
		txs[pair].insert(user_id, tot_tx, Tx(TX_CANCEL, order_id, order.type, order.price, order.volume, timestamp));
		++tot_tx;

		orders[pair].erase(user_id, order_id);
		
		printf("Order %ld cancelled!\n", order_id);
	} else {
		printf("Cancellation fails!\n");
	}
}


void settle() {
	// (SETTLE, timestamp, pair)
	long timestamp;
	int pair;
	scanf("%ld %d", &timestamp, &pair);
	
	while (orderbook[pair].settle()) {
		ULL sell_price = orderbook[pair].sell_book.begin()->first.first;
		long sell_id = orderbook[pair].sell_book.begin()->first.second;
		long seller_id = orderbook[pair].sell_book[make_pair(sell_price, sell_id)];

		ULL buy_price = orderbook[pair].buy_book.begin()->first.first;
		long buy_id = orderbook[pair].buy_book.begin()->first.second;
		long buyer_id = orderbook[pair].buy_book[make_pair(buy_price, buy_id)];
		
		if (expiration_check(timestamp, seller_id, COINREF[pair][SELL]) 
				|| expiration_check(timestamp, buy_id, COINREF[pair][BUY])) {
			continue;
		}
		
		Order sell_order = orders[pair].getOrder(seller_id, sell_id);
		Order buy_order = orders[pair].getOrder(buyer_id, buy_id);
		ULL volume = min(sell_order.volume, buy_order.volume);

		txs[pair].insert(seller_id, tot_tx, Tx(buyer_id, sell_id, SELL, sell_order.price, volume, timestamp));
		++tot_tx;
		txs[pair].insert(buyer_id, tot_tx, Tx(seller_id, buy_id, BUY, buy_order.price, volume, timestamp));
		++tot_tx;
		printf("sell_price: %lld; buy_price: %lld; volume: %lld.\n", sell_price, buy_price, volume);

		deposits[COINREF[pair][SELL]].settle(seller_id, volume);
		deposits[COINREF[pair][BUY]].settle(buyer_id, volume * buy_price);

		if (sell_order.volume > volume) {
			orders[pair].settle(seller_id, sell_id, volume);
		} else {
			orders[pair].erase(seller_id, sell_id);
			orderbook[pair].erase(SELL, sell_price, sell_id);
		}

		if (buy_order.volume > volume) {
			orders[pair].settle(buyer_id, buy_id, volume);
		} else {
			orders[pair].erase(buyer_id, buy_id);
			orderbook[pair].erase(BUY, buy_price, buy_id);
		}
	}
}

void check() {
	// (CHECK, timestamp, user_id)
	long timestamp, user_id;
	scanf("%ld %ld", &timestamp, &user_id);
	for (int i = 0; i < COIN_NUM; ++i) {
		expiration_check(timestamp, user_id, i);
	}

	printf("Deposits:\n");
	for (int i = 0; i < COIN_NUM; ++i) {
		//deposits
		printf("    %s: ", COIN[i].c_str());
		if (deposits[i].find(user_id)) {
			deposits[i].book[user_id].output();
		} else {
			printf("No deposit yet.\n");
		}
	}

	for (int i = 0; i < PAIR_NUM; ++i) {
		printf("%s: \n", EXCHANGE[i].c_str());
		//orderbook
		//sell_book
		printf("    Sell orders:\n");
		if (orderbook[i].sell_book.empty()) {
			printf("        No sell order yet.\n");
		} else {
			for (map<pair<ULL, long>, long>::iterator it = orderbook[i].sell_book.begin();
					it != orderbook[i].sell_book.end(); ++it) {
				printf("        price: %lld; volume: %lld\n", it->first.first,
						orders[i].book[it->second][it->first.second].volume);
			}
		}
		//buy_book
		printf("    Buy orders:\n");
		if (orderbook[i].buy_book.empty()) {
			printf("        No buy order yet.\n");
		} else {
			for (map<pair<ULL, long>, long>::iterator it = orderbook[i].buy_book.begin();
					it != orderbook[i].buy_book.end(); ++it) {
				printf("        price: %lld; volume: %lld\n", it->first.first,
						orders[i].book[it->second][it->first.second].volume);
			}
		}

		//orders
		printf("    User orders:\n");
		if (orders[i].find(user_id)) {
			for (map<long, Order>::iterator it = orders[i].book[user_id].begin();
					it != orders[i].book[user_id].end(); ++it) {
				printf("        Order %ld: ", it->first);
				it->second.output();
			}
		} else {
			printf("        No order yet.\n");
		}
	
		//txs
		printf("    User txs:\n");
		if (txs[i].find(user_id)) {
			for (map<long, Tx>::iterator it = txs[i].book[user_id].begin();
					it != txs[i].book[user_id].end(); ++it) {
				printf("        Tx %ld: ", it->first);
				it->second.output();
			}
		} else {
			printf("        No tx yet.\n");
		}
	}

}

int main() {
	freopen("orderbook.in", "r", stdin);
	freopen("orderbook.out", "w", stdout);
    int n;
    scanf("%d", &n); //get commands#

    for (int o = 0; o < n; ++o) {
		printf("COMMAND %d:\n", o);
        char st[100];
        scanf("%s", st);
       
		if (string(st) == "DEPOSIT") {
			// (DEPOSIT, timestamp, user_id, coin, volume)
			deposit();
		} else if (string(st) == "WITHDRAW") { 
			// (WITHDRAW, timestamp, user_id, coin, volume)
			withdraw();			
		} else if (string(st) == "RENEW") {
			// (RENEW, timestamp, user_id, coin)
			renew();
		} else if (string(st) == "BUY") {
			// (BUY, timestamp, user_id, pair, price, volume)
			order(BUY);
		} else if (string(st) == "SELL") {
			// (SELL, timestamp, user_id, pair, price, volume)
			order(SELL);
		} else if (string(st) == "CANCEL") {
			// (CANCEL, timestamp, user_id, pair, order_id)
			cancel();
		} else if (string(st) == "SETTLE") { 
			// (SETTLE, timestamp, pair)
			settle();
		} else if (string(st) == "CHECK") {
			// (CHECK, timestamp, user_id)
			check();
		}
		printf("\n");
    }

    fclose(stdin);
	fclose(stdout);
    return 0; 
}

