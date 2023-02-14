from log_analysis import get_log_file_path_from_cmd_line, filter_log_by_regex
import pandas as pd
import re

def main():
    log_file = get_log_file_path_from_cmd_line(1)
    dpt_tally = tally_port_traffic(log_file)

    for dpt, count in dpt_tally.items():
        if count > 100:
            generate_port_traffic_report(log_file, dpt)

    generate_invalid_user_report(log_file)
    generate_source_ip_log(log_file, '220.195.35.40')
    pass

def tally_port_traffic(log_file):
    dest_port_logs = filter_log_by_regex(log_file, r'DPT=(.+?) ')[1]
    
    dpt_tally = {}
    for dpt in dest_port_logs:
        dpt = dpt[0]
        dpt_tally[dpt] = dpt_tally.get(dpt, 0) + 1


    return dpt_tally

def generate_port_traffic_report(log_file, port_number):
    regex = r"^(.{6}) (.{8}) .*SRC=(.+) DST=(.+?) .*SPT=(.+) " + f"DPT=({port_number}) "
    capture_data = filter_log_by_regex(log_file, regex)[1]

    report_df = pd.DataFrame(capture_data)
    report_header = ('Date', 'Time', 'Source IP Address', 'Destination IP Address', 'Source Port', 'Destination Port')
    report_df.to_csv(f'destination_port_{port_number}_report.csv', index=False, header=report_header)
    
def generate_invalid_user_report(log_file):
    regex= r"^(.{6}) (.{8}) .*user (.*) from (.+)"
    capture_data = filter_log_by_regex(log_file, regex)[1]
     
    report_df = pd.DataFrame(capture_data)
    report_header = ('Date', 'Time', 'Username', 'IP address')
    report_df.to_csv(f'invalid_users.csv', index=False, header=report_header)

def generate_source_ip_log(log_file, ip_address):

    regex = r"(.*SRC=)" + f"({ip_address})" + r"(.*)"
    capture_data = filter_log_by_regex(log_file, regex)[0]
    
    report_df = pd.DataFrame(capture_data)
    address = re.sub(r"\.", "_", ip_address)
    report_df.to_csv(f'source_ip_{address}.log', index=False, header=None)

    return

if __name__ == '__main__':
    main()