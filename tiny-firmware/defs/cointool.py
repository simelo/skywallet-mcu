import glob
import os
import sys

from mako import template

import coin

BTC_COINS_FOLDER = './defs/bitcoin/'
if 'BTC_COINS_FOLDER' in os.environ.keys():
    BTC_COINS_FOLDER = os.environ.get('BTC_COINS_FOLDER')


def render(srcs):
    """
    Render all files 'filename.mako' on result file 'filename'

    :param srcs: Root folder for files to render.
    :return: void
    """
    # Find files in directories
    files = []
    for src in srcs:
        if not os.path.exists(src):
            print(f'Path {src} does not exist')
        elif os.path.isdir(src):
            files.extend(glob.glob(os.path.join(src, "*.mako")))
        else:
            files.append(src)

    # Load necessary coins definitions
    btc_coins = coin.load_btc_coins(BTC_COINS_FOLDER)

    # Render each file
    for file in files:
        if not file.endswith('.mako'):
            print(f'File {file} does not end with .mako')
            return
        else:
            target = file[: -len('.mako')]
            print(f'Rendering file {file}')
            with open(target, 'w') as dst:
                temp = template.Template(filename=file)
                result = temp.render(btc_coins=btc_coins)
                dst.write(result)


srcs = sys.argv[1:]
render(srcs)
