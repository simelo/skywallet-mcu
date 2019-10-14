import glob
import json
import os


def load_coins(srcs):
    """
    Load all json files on srcs as coin definition

    :param srcs: Sources with coins definitions
    :return: List of dictionaries(coins definitions)
    """
    files = []
    # Find all .json files on srcs
    for src in srcs:
        if not os.path.exists(src):
            print(f'Path {src} does not exist')
            return
        elif not os.path.isdir(src):
            print(f'Path {src} not is folder.')
            return
        else:
            files.extend(glob.glob(os.path.join(src, '*.json')))

    coins = []

    # Build all bitcoin
    for filename in files:
        with open(filename) as file:
            obj = json.load(file)
            coins.append(obj)
    return coins


def load_btc_coins(src):
    """
    Load BTC_COINS definitions from src and set-update some fields for this coins.

    :param src: Source with BTC_COINS json definitions
    :return: List of dictionaries(coins definitions)
    """
    print(f'Loading btc coins from {src}')
    coins = load_coins([src])
    if coins:
        for coin in coins:
            coin.update(
                name=coin["coin_label"],
                shortcut=coin['coin_shortcut'],
                key='bitcoin:{}'.format(coin['coin_shortcut']),
            )
    return coins
