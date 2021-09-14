import requests


def get_ip_analysis():
    """Receive the input as IP address and request analysis information from Virustotal
    and display specify details as country and most recent analysis stat of IP address that received from Virustotal."""
    # Setting up the API key and URL for requesting.
    api_key = "2216cdde5e43cf9bd907d5da44298e09cbc14e6be25b8e398b965b55663c74d0"
    url = 'https://www.virustotal.com/api/v3/ip_addresses/'
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                             "Chrome/70.0.3538.77 Safari/537.36", 'x-apikey': '%s' % api_key}

    # Receive an input string as an IP address to request analysis results.
    ip_addr = input("Enter the IP Address: ")

    # Send request to Virustotal
    response = requests.get(url + "%s" % ip_addr, headers=headers).json()
    
    # Manage and collect information.
    total_analyses = sum(response['data']['attributes']['last_analysis_stats'].values())
    analysis_stat = response['data']['attributes']['last_analysis_stats']

    # Display the IP address analysis results.
    print("\nIP Address Details\nCountry: ", response['data']['attributes']['country'])
    print("Analysis Stat: The analysis results indicated that this IP address was")
    for attribute in analysis_stat.keys():
        print("    -", attribute.upper(), "at", "%.2f" % (analysis_stat[attribute] / total_analyses * 100) +
              "% (" + str(analysis_stat[attribute]) + " from " + str(total_analyses) + ")")


get_ip_analysis()
