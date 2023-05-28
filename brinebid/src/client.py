#!/usr/bin/env python3

import os
import sys
import time
import pickle
import base64
import requests
import urllib.parse
import argparse

try:
    import websockets
    from websockets.sync.client import connect
    import pytermgui as ptg
except ImportError:
    print("Please install deps...")
    print("pip3 install -U websockets pytermgui requests")
    exit(1)

# Patch pytermgui to support ansi images
_draw = ptg.window_manager.Compositor.draw
def draw(self, *args, **kwargs):
    _draw(self, *args, **kwargs)

    win = Client.instance
    cur_win = win.current_window

    if not cur_win or not win.img:
        win.img_visible = False
        return

    term = ptg.term.get_terminal()
    theight = term.height
    twidth = term.width

    pos = cur_win.pos

    img_x = (twidth - win.img_width) // 2
    img_y = pos[1] + win.img_offset

    ptg.ansi_interface.cursor_home()
    ptg.ansi_interface.cursor_down(num=img_y)
    for l in win.img.split('\n'):
        ptg.ansi_interface.cursor_right(num=img_x)
        term.write(l+'\n')
    ptg.ansi_interface.cursor_home()

ptg.window_manager.Compositor.draw = draw

# Support paste
_handle_key = ptg.InputField.handle_key
def handle_key(self, key):
    res = _handle_key(self, key)
    if not res and len(key) > 1 and not key.startswith("\x1b["):
        with open('/tmp/z','a') as f:
            f.write(key+'\n')
        for char in key:
            self.handle_key(char)
        return True
    return res
ptg.InputField.handle_key = handle_key


STYLES = """
config:
    InputField:
        styles:
            prompt: dim italic
            cursor: '@72'
    Label:
        styles:
            value: dim bold

    Window:
        styles:
            border: '60'
            corner: '60'

    Container:
        styles:
            border: '96'
            corner: '96'
    Button:
        styles:
            label: cyan
    Window:
        styles:
            fill: red

    InputField:
        styles:
            fill: red
            prompt: red
"""

ptg.get_terminal().forced_colorsystem = ptg.ColorSystem.TRUE
ptg.palette.regenerate(primary="cyan", secondary="white")
with ptg.YamlLoader() as loader:
    loader.load(STYLES)

def send_pickle(c, arg):
    obj = Message(arg)
    data = pickle.dumps(obj, protocol=3)
    data = base64.b64encode(data).decode('latin-1')
    c.ws.send(data)

def get_pickle(c):
    data = c.ws.recv()
    data = base64.b64decode(data)
    obj = pickle.loads(data)
    return obj

# ========================

class Message(object):
    def __init__(self, arg):
        self.sender = 'user'
        self.body = arg

class Response(object):
    def __init__(self, res, msg):
        self.success = res
        self.message = msg

class Request(object):
    def __init__(self):
        pass

    def send(self, c):
        try:
            send_pickle(c, self)
            return get_pickle(c)
        except websockets.exceptions.ConnectionClosedError as e:
            c.restart()
            return None
        except Exception as e:
            return None


class AuctionProperty(object):
    def __init__(self, uuid, name, desc, end):
        self.uuid = uuid
        self.property_name = name
        self.description = desc
        self.end_time = end

class AuctionInfoRequest(Request):
    def __init__(self):
        pass

class AuctionInfoResponse(object):
    def __init__(self, prop):
        self.property = prop

class PropertyToken(object):
    def __init__(self, uuid, name, desc, val, image):
        self.uuid = uuid
        self.property_name = name
        self.description = desc
        self.estimated_value = 0

class AuctionBidRequest(Request):
    def __init__(self, bid):
        self.bid = bid

class AuctionBidResponse(object):
    def __init__(self, res, msg, prop):
        self.success = res
        self.message = msg
        self.property = prop

class Wallet(object):
    def __init__(self, worth, bal, props, loans):
        self.net_worth = worth
        self.balance = bal
        self.properties = props
        self.loans = loans

class WalletRequest(Request):
    def __init__(self):
        pass

class WalletResponse(object):
    def __init__(self, **args):
        self.wallet = Wallet(**args)

class NewLoanRequest(Request):
    def __init__(self):
        pass

class NewLoanResponse(object):
    def __init__(self, res, msg, value):
        self.success = res
        self.message = msg
        self.value = value

class PayLoanRequest(Request):
    def __init__(self, index):
        self.loan_index = index

class PayLoanResponse(object):
    def __init__(self, res, msg):
        self.success = res
        self.message = msg

class SellPropertyRequest(Request):
    def __init__(self, uuid):
        self.uuid = uuid

class SellPropertyResponse(object):
    def __init__(self, res, msg, price):
        self.success = res
        self.message = msg
        self.sale_price = price

class ResetRequest(Request):
    def __init__(self):
        pass
class ResetResponse(Request):
    def __init__(self, res, msg):
        self.success = res
        self.message = msg

# ========================

def format_currency(value):
    return "${:,.0f}".format(value)

class Client(object):
    def __init__(self, ws, ptgm, args):
        self.ws = ws
        self.page = 'home'
        self.ptgm = ptgm
        self.args = args

        self.wallet = None
        self.wallet_timestamp = 0
        self.current_lot = None
        self.current_window = None
        self.error_msg = []
        self.img = None
        self.img_offset = 0
        self.img_visible = False

        self.width = 60
        self.height = 30

        self.page_before_disconnect = None

        Client.instance = self
        ptg.term.get_terminal().subscribe(0, self.resize)

        ptg.tim.define("!auction_time", self.auction_time_left)

    def resize(self, *args):
        self.goto(self.page)

    def goto(self, page):
        if self.page_before_disconnect:
            page = self.page_before_disconnect
            self.page_before_disconnect = None

        self.page = page

        last_window = None
        if self.current_window is not None:
            last_window = self.current_window

        self.img = None
        self.img_offset = 0
        self.img_visible = False

        if self.page == 'home':
            self.render_home()
        if self.page == 'reset':
            self.render_reset()
        if self.page == 'wallet':
            self.render_wallet()
        if self.page == 'auction':
            self.render_auction()
        if self.page == 'bid':
            self.render_bid()
        if self.page.startswith('property-'):
            self.render_property(self.page.split('-')[-1])
        if self.page.startswith('loan-'):
            self.render_loan(self.page.split('-')[-1])

        if last_window is not None:
            try:
                last_window.close(animate=False)
            except:
                pass
        if self.current_window:
            self.current_window.height = self.height
            self.current_window.width = self.width

            self.current_window.center()

    # Pick a good resolution for current terminal size
    def get_image(self, uuid, off=0):
        term = ptg.term.get_terminal()
        theight = term.height
        twidth = term.width

        diff = theight - self.height - 4

        if diff < 8:
            self.img = None
            return

        if diff < 15:
            self.img_height = 25 // 2
            self.img_width = 25
        if diff < 17:
            self.img_height = 30 // 2
            self.img_width = 30
        elif diff < 27:
            self.img_height = 40 // 2
            self.img_width = 40
        else:
            self.img_height = 50 // 2
            self.img_width = 50
        
        img_name = f'{uuid}_{self.img_width}x{self.img_width}.ansi'

        cache_path = f'/tmp/.client_cache/images/{img_name}'
        local_path = f'./images/{img_name}'
        if os.path.exists(cache_path):
            img_path = f'file://{cache_path}'
        elif os.path.exists(local_path):
            img_path = f'file://{local_path}'
        else:
            img_path = f'http://{self.args.HOST}:{self.args.PORT}/images/{img_name}'

        try:
            if img_path.startswith('file://'):
                img_path = img_path[7:]
                with open(img_path, 'r') as f:
                    img = f.read()
            else:
                out = requests.get(img_path)
                if out.status_code != 200:
                    self.img = None
                    return
                img = out.text
        except Exception as e:
            print(e)
            self.img = None
            return


        with open(cache_path, 'w') as f:
            f.write(img)
        
        self.img = img
        self.img_offset = off

    def clear_cache(self):
        self.wallet = None
        self.current_lot = None

    def get_current_lot(self):
        if self.current_lot:
            if self.current_lot.end_time > time.time():
                return self.current_lot
        v = AuctionInfoRequest().send(self)
        if v is None:
            return None
        self.current_lot = v.body.property
        return self.current_lot
    
    def get_current_wallet(self):
        if self.wallet:
            if self.wallet_timestamp + 30 > time.time():
                return self.wallet
        v = WalletRequest().send(self)
        if v is None:
            return None
        self.wallet = v.body.wallet
        self.wallet_timestamp = time.time()
        return self.wallet
        
    def auction_time_left(self, *args):
        if not self.current_lot:
            return 'n/a'

        diff = self.current_lot.end_time - time.time()

        if diff < -30:
            # refresh
            self.goto('auction')
            return 'Auction Ended'

        if diff < 0:
            return 'Auction Ended'
        
        return '{}:{:02}'.format(int((diff % 3600) // 60), int(diff % 60))

    def render_bid(self):
        self.get_current_wallet();
        if self.wallet is None:
            self.error_msg.append('Error: Could not get wallet')
            self.goto('home')
            return

        lot = self.get_current_lot()
        if lot is None:
            self.error_msg.append('Error: Could not get current lot')
            self.goto('home')
            return

        self.width = 60
        extra_lines = (len(lot.description) // (self.width-3)) + 1
        if (len(self.error_msg) > 0):
            extra_lines += (len('Notice: ' + self.error_msg[-1]) // (self.width-3)) + 1

        self.height = 25 + extra_lines
        self.get_image(lot.uuid, off=7)
        self.width = 60
        if self.img:
            self.height += self.img_height

        bid_input = ptg.InputField("", prompt="Bid Amount: $", name="bid_amount")
        bid_input.static_width = 30

        window = ptg.Window(
            "Services",
            ["My Wallet", lambda x: self.goto('wallet')],
            ["My Properties", lambda x: self.goto('property-0')],
            ["--> Current Property Auction <--", lambda x: self.goto('auction')],
            "---",
            "[bold accent]Bidding For Property[/] [!auction_time]\n",
            "\n"*self.img_height if self.img else "",
            f"\n[bold accent]Current Lot:[/] {lot.uuid}\n",
            f"[bold accent]Name:[/] {lot.property_name}\n",
            f"{lot.description}\n",
            "",
            f"\n\n[bold accent]Your Balance:[/] {format_currency(self.wallet.balance)} SandDollars\n",
            "[bold accent]Place Bid:[/]",
            bid_input,
            f"[bold accent]Notice:[/] [coral]{self.error_msg.pop()}[/]\n"
                if len(self.error_msg) > 0 else "",
            ["Submit", lambda x: self.make_bid(bid_input.value)],
        )
        self.current_window = window
        self.ptgm.add(window, animate=False)

    def make_bid(self, bid):
        if self.current_lot is None:
            self.goto('auction')
            return
        if self.current_lot.end_time < time.time():
            self.goto('auction')
            return
        try:
            bid = int(bid.replace('$','').replace(',',''))
        except:
            self.error_msg.append("Invalid Bid Amount")
            self.goto('bid')
            return
        r = AuctionBidRequest(int(bid)).send(self)

        if r is None:
            self.error_msg.append("Error Placing Bid")
            self.goto('bid')
            return

        self.clear_cache()
        if r.body.success == 'success':
            self.goto('bid')
            self.error_msg.append(r.body.message)
        else:
            self.error_msg.append(r.body.message)
            self.goto('bid')


    def render_auction(self):
        self.ptgm.layout.add_slot("Body")
        lot = self.get_current_lot()
        if lot is None:
            self.error_msg.append('Error: Could not get current lot')
            self.goto('home')
            return
        self.current_lot = lot

        self.width = 60
        extra_lines = (len(lot.description) // (self.width - 3)) + 1

        self.height = 18 + extra_lines
        self.get_image(lot.uuid, off=7)
        if self.img:
            self.height += self.img_height

        window = ptg.Window(
            "Services",
            ["My Wallet", lambda x: self.goto('wallet')],
            ["My Properties", lambda x: self.goto('property-0')],
            ["--> Current Property Auction <--", lambda x: self.goto('auction')],
            "---",
            "[bold accent]Property Auction[/] [!auction_time]\n",
            "\n"*self.img_height if self.img else "",
            f"\n[bold accent]Current Lot:[/] {lot.uuid}\n",
            f"[bold accent]Name:[/] {lot.property_name}\n",
            f"{lot.description}\n",
            "",
            ["Place Bid For Property", lambda x: self.goto('bid')],
        )
        self.current_window = window
        self.ptgm.add(window, animate=False)

    def sell_property(self, uuid):
        r = SellPropertyRequest(uuid).send(self)
        if r is None:
            self.error_msg.append("Error Selling Property")
            self.goto('wallet')
            return
        self.error_msg.append(r.body.message)
        self.clear_cache()
        self.goto('wallet')

    def render_property(self, ind):
        ind = int(ind)
        self.get_current_wallet();
        if self.wallet is None:
            self.error_msg.append('Error: Could not get wallet')
            self.goto('home')
            return

        if ind < len(self.wallet.properties): 
            prop = self.wallet.properties[ind]
        else:
            prop = None

        if not prop:
            self.width = 60
            self.height = 20
            window = ptg.Window(
                "Services",
                ["My Wallet", lambda x: self.goto('wallet')],
                ["--> My Properties <--", lambda x: self.goto('property-0')],
                ["Current Property Auction", lambda x: self.goto('auction')],
                "---",
                "[bold accent]Your Properties[/]\n\n",
                "You Have No Properties"
                "",
            )
        else:
            self.width = 60
            extra_lines = (len(prop.description) // (self.width - 3)) + 1

            self.height = 24 + extra_lines
            self.get_image(prop.uuid, off=11)
            self.width = 60
            if self.img:
                self.height += self.img_height

            has_more = len(self.wallet.properties) > ind + 1
            num_props = len(self.wallet.properties)

            self.ptgm.layout.add_slot("Body")
            window = ptg.Window(
                "Services",
                ["My Wallet", lambda x: self.goto('wallet')],
                ["--> My Properties <--", lambda x: self.goto('property-0')],
                ["Current Property Auction", lambda x: self.goto('auction')],
                "---",
                "[bold accent]Your Properties[/]\n"
                f"You have {num_props} Propert{'y' if num_props==1 else 'ies'}\n\n",
                f"[bold accent]Property #:[/] {prop.uuid}\n",
                "\n"*self.img_height if self.img else "",
                f"[bold accent]Name:[/] {prop.property_name}\n",
                f"[bold accent]Estimated Property Value:[/] {format_currency(prop.estimated_value)} SandDollars\n",
                f"{prop.description}\n",
                ["Sell Property", lambda x: self.sell_property(prop.uuid)],
                "",
                ["<-- Previous", lambda x: self.goto(f'property-{ind-1}')]
                    if ind > 0 else "",
                ["Next -->", lambda x: self.goto(f'property-{ind+1}')]
                    if has_more else
                "",
            )
        self.current_window = window
        self.ptgm.add(window, animate=False)

    def pay_loan(self, ind):
        r = PayLoanRequest(ind).send(self)
        if r is None:
            self.error_msg.append("Error Paying Loan")
            self.goto('wallet')
            return
        self.clear_cache()
        self.error_msg.append(r.body.message)
        if r.body.success != False:
            self.goto('wallet')
        else:
            self.goto(f'loan-{ind}')

    def render_loan(self, ind):
        ind = int(ind)
        self.get_current_wallet();
        if self.wallet is None:
            self.error_msg.append('Error: Could not get wallet')
            self.goto('home')
            return
        

        if ind < len(self.wallet.loans):
            loan = self.wallet.loans[ind]
        else:
            loan = None

        if not loan:
            self.width = 60
            self.height = 20
            window = ptg.Window(
                "Services",
                ["My Wallet", lambda x: self.goto('wallet')],
                ["My Properties", lambda x: self.goto('property-0')],
                ["Current Property Auction", lambda x: self.goto('auction')],
                "---",
                "[bold accent]Unpaid Loans[/]\n\n",
                "You Have No Outstanding Loans"
                "",
            )
        else:
            self.height = 23
            self.width = 60

            has_more = len(self.wallet.loans) > ind + 1
            num_loans = len(self.wallet.loans)

            self.ptgm.layout.add_slot("Body")
            window = ptg.Window(
                "Services",
                ["My Wallet", lambda x: self.goto('wallet')],
                ["My Properties", lambda x: self.goto('property-0')],
                ["Current Property Auction", lambda x: self.goto('auction')],
                "---",
                "[bold accent]Unpaid Loans[/]\n\n",
                f"You have {num_loans} Unpaid Loan{'' if num_loans==1 else 's'}\n\n",
                f"[bold accent]Loan #:[/] {ind}\n",
                f"[bold accent]Initial Value:[/] {format_currency(loan['amount'])} SandDollars\n",
                f"[bold accent]Current Value:[/] {format_currency(loan['with_intrest'])} SandDollars\n",
                (f"[bold accent]Notice:[/] [coral]{self.error_msg.pop()}[/]\n"
                    if len(self.error_msg) > 0 else ""),
                ["Pay Loan In Full", lambda x: self.pay_loan(ind)],
                ["<-- Previous", lambda x: self.goto(f'loan-{ind-1}')]
                    if ind > 0 else "",
                ["Next -->", lambda x: self.goto(f'loan-{ind+1}')]
                    if has_more else
                "",
            )
        self.current_window = window
        self.ptgm.add(window, animate=False)

    def new_loan(self):
        r = NewLoanRequest().send(self)
        if r is None:
            self.error_msg.append("Error Creating Loan")
            self.goto('wallet')
            return
        self.clear_cache()
        self.error_msg.append(r.body.message)
        self.goto('wallet')

    def render_wallet(self):
        self.get_current_wallet();
        if self.wallet is None:
            self.error_msg.append('Error: Could not get wallet')
            self.goto('home')
            return

        prop_sum = sum([p.estimated_value for p in self.wallet.properties])
        loan_sum = sum([l['with_intrest'] for l in self.wallet.loans])

        self.width = 60
        self.height = 30


        self.ptgm.layout.add_slot("Body")
        window = ptg.Window(
            "Services",
            ["--> My Wallet <--", lambda x: self.goto('wallet')],
            ["My Properties", lambda x: self.goto('property-0')],
            ["Current Property Auction", lambda x: self.goto('auction')],
            "---",
            "[bold accent]Your Wallet[/]\n\n",
            "",
            f"[bold accent]Net Worth:[/] {format_currency(self.wallet.netWorth)} SandDollars\n",
            f"[bold accent]SandDollar Balance:[/] {format_currency(self.wallet.balance)}\n",
            f"[bold accent]Estimated Property Value:[/] {format_currency(prop_sum)}\n",
            f"[bold accent]Loan Value:[/] {format_currency(-loan_sum)}\n\n",
            f"[bold accent]Notice:[/] [coral]{self.error_msg.pop()}[/]\n"
                if len(self.error_msg) > 0 else "",
            ["See / Pay Loans", lambda x: self.goto('loan-0')],
            ["Take Out New Loans $1M - $10M", lambda x: self.new_loan()],
            "",
        )
        self.current_window = window
        self.ptgm.add(window, animate=False)
    
    def reset_challenge(self):
        ResetRequest().send(self)
        self.goto('home')
    
    def render_reset(self):
        self.width = 60
        self.height = 20
        window = ptg.Window(
            "RESET ACCOUNT\n\n",
            "Are you sure you want to reset your account?\n",
            "This will delete all your properties and loans and reset your balance\n",
            "This deletion is permanent and cannot be undone\n",

            ["NO, GO BACK", lambda x: self.goto('home')],
            ["YES, RESET MY ACCOUNT", lambda x: self.reset_challenge()],
        )
        self.current_window = window
        self.ptgm.add(window, animate=False)

    def check_ticket(self, then, *args, force=False):
        if self.ws and not force:
            self.goto(then)
            return 
        try:
            with open('/tmp/.client_cache/ticket') as f:
                ticket = f.read()
        except:
            ticket = ''

        ticket = ticket.strip()

        if len(ticket) == 0 or force:

            # Stop all that ansi nonsense
            self.ptgm.stop()
            ptg.ansi_interface.clear()
            ptg.ansi_interface.cursor_home()
            ptg.ansi_interface.show_cursor()
            ptg.ansi_interface.set_echo()
            ptg.ansi_interface.report_mouse('hover', stop=True)
            ptg.ansi_interface.reset()

            ticket = input("Ticket please: ").strip()
            s = ptg.ansi_interface.restore_screen()
        
        ticket = ticket.strip()
        if len(ticket) == 0:
            self.error_msg.append("Access Ticket is Required!")
            self.goto('home')
            return

        self.ticket = ticket
        ticket_url = urllib.parse.quote(ticket)
        with websockets.sync.client.connect(
            f'ws://{self.args.HOST}:{self.args.PORT}',
            subprotocols=[ticket_url]
        ) as ws:
            self.ws = ws
            with open('/tmp/.client_cache/ticket','w') as f:
                f.write(self.ticket)
            self.ptgm.stop()
            with ptg.WindowManager() as manager:
                Client(ws, manager, self.args).goto(then, *args)



    def render_home(self):
        self.width = 60
        self.height = 32

        ticket = None
        if os.path.exists('/tmp/.client_cache/ticket'):
            with open('/tmp/.client_cache/ticket') as f:
                ticket = f.read()

        self.ptgm.layout.add_slot("Body")
        window = ptg.Window(
            "",
            "[bold accent]Welcome to BrineBid, the number one platform for bidding on Property Tokens*. Join thousands of other real-estate mogals who are striking it rich** in digital realty.\nOwn the concept of ownership today![/]\n\n",
            "[bold] Enter Access Ticket to Proceed:" if not ticket else "",
            ["Add Access Ticket" if not ticket else "Change Access Ticket", lambda x: self.check_ticket('home', force=True)],
            f"[bold accent]Notice:[/] [coral]{self.error_msg.pop()}[/]\n"
                if len(self.error_msg) > 0 else "",
            "[bold]=========== DASHBOARD ===========[/]",
            ["My Wallet", lambda x: self.check_ticket('wallet')],
            ["My Properties", lambda x: self.check_ticket('property-0')],
            ["Current Property Auction", lambda x: self.check_ticket('auction')],
            "\n\n\n\n\n[bold] Drowning in Debt?",
            ["DECLARE BANKRUPTCY", lambda x: self.check_ticket('reset')],
            "[dim @surface-3]\n\n*Owning Property Tokens do not imply ownership of any\nphysical property. Property Tokens are not securities   and are not backed by any government or central bank.   Property Tokens are not redeemable for any underlying   pysical asset.\n**SandDollars price is speculative and does not have a  fixed or 1-to-1 USD price guarantee[/]",
        )
        self.current_window = window
        self.ptgm.add(window, animate=False)

    def restart(self):
        args = sys.argv
        if '--page' not in args:
            args += ['--page', self.page]
        os.execv(sys.executable, [sys.executable] + args)
        exit(0)
        

def main(args):
    with ptg.WindowManager() as manager:
        c = Client(None, manager, args)
        if args.page == 'home':
            c.goto('home')
        else:
            c.check_ticket(args.page)
        


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', dest='HOST', default='brinebid-qfzqys6gg7lgi.shellweplayaga.me')
    parser.add_argument('--port', dest='PORT', default='10001')
    parser.add_argument('--images', dest='IMAGES', default='./images')
    parser.add_argument('--page', dest='page', default='home')
    args = parser.parse_args()

    os.makedirs("/tmp/.client_cache", exist_ok=True)
    os.makedirs("/tmp/.client_cache/images", exist_ok=True)
    main(args)


