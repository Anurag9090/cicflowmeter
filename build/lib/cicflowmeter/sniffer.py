import argparse

from scapy.sendrecv import AsyncSniffer

from .flow_session import generate_session_class

import threading as th  

from datetime import datetime


def create_sniffer(
    input_file, input_interface, output_mode, output_file, url_model=None
):
    assert (input_file is None) ^ (input_interface is None)

    NewFlowSession = generate_session_class(output_mode, output_file, url_model)

    if input_file is not None:
        return AsyncSniffer(
            offline=input_file,
            filter="ip and (tcp or udp)",
            prn=None,
            session=NewFlowSession,
            store=False,
        )
    else:
        return AsyncSniffer(
            iface=input_interface,
            filter="ip and (tcp or udp)",
            prn=None,
            session=NewFlowSession,
            store=False,
        )


def main():
    parser = argparse.ArgumentParser()

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="input_interface",
        help="capture online data from INPUT_INTERFACE",
    )

    input_group.add_argument(
        "-f",
        "--file",
        action="store",
        dest="input_file",
        help="capture offline data from INPUT_FILE",
    )

    output_group = parser.add_mutually_exclusive_group(required=False)
    output_group.add_argument(
        "-c",
        "--csv",
        "--flow",
        action="store_const",
        const="flow",
        dest="output_mode",
        help="output flows as csv",
    )

    url_model = parser.add_mutually_exclusive_group(required=False)
    url_model.add_argument(
        "-u",
        "--url",
        action="store",
        dest="url_model",
        help="URL endpoint for send to Machine Learning Model. e.g http://0.0.0.0:80/prediction",
    )
    
    # added timer agrument
    timer = parser.add_mutually_exclusive_group(required=False)
    timer.add_argument(
        "-t",
        action="store",
        dest="timer",
        help="give the time interval for capture.",
    )

    parser.add_argument(
        "output",
        help="output file name (in flow mode) or directory (in sequence mode)",
    )

    args = parser.parse_args()
    
    # changed the output file name to avoid any mismatch of collecting continious traffic    
    date_str = str(datetime.today())
    if '/' in args.output:
        args.output = args.output.rsplit('/',1)[0] + "/" +date_str.split('.', -1)[0].replace(' ', '-') + '.csv'
    else:
        args.output = date_str.split('.', -1)[0].replace(' ', '-') + '.csv'


    sniffer = create_sniffer(
        args.input_file,
        args.input_interface,
        args.output_mode,
        args.output,
        args.url_model,
    )
    sniffer.start()
    
    if(args.timer == None):
        args.timer = 60
    
    # using to timer to quit the script
    S = th.Timer(int(args.timer), sniffer.stop)
    S.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        S.cancel()
        sniffer.stop()
    finally:
        sniffer.join()


if __name__ == "__main__":
    main()
