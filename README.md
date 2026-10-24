# SOC-Investigation
Practical SOC investigations covering network traffic analysis, log analysis, and Windows forensics.
Practical Network Traffic Analysis with TShark

Overview

This project documents hands-on practice analyzing HTTP and DNS traffic using TShark in Ubuntu on WSL. The exercises focus on extracting protocol fields from packet capture files, filtering traffic, counting repeated values, and understanding the relationship between DNS queries and responses.

Tools Used

TShark: Command-line packet analysis

Wireshark: Graphical packet analysis

Ubuntu on WSL: Linux command-line environment

awk, sort, uniq, head: Text processing and output summarization

1. HTTP Traffic Analysis

Capture file: http.cap

1.1 Extracting HTTP Request URIs

HTTP request URIs can be extracted using the field http.request.uri.

The TShark options used in this exercise were:

-r — reads the packet capture file.

-Y — applies a display filter.

-T fields — outputs selected fields.

-e — specifies the field to extract.

The filter http.request selects HTTP request packets.

1.2 Filtering Long URIs with awk

After extracting the URI values, awk was used to display lines longer than 50 characters.

awk 'length($0) > 50 {print $0}'

How it works:

length($0) calculates the length of the current line.

> 50 checks whether the line exceeds 50 characters.

{print $0} prints the complete matching line.

This technique can help identify long request URIs for further inspection.

Lesson learned: PCAP files contain binary packet data, so protocol fields should be extracted with TShark before processing the resulting text with utilities such as awk.

1.3 Counting Repeated Request URIs

The following pipeline was used to count repeated HTTP request URIs:

tshark -r http.cap -Y "http.request.uri" -T fields -e http.request.uri | sort | uniq -c | sort -nr

Pipeline breakdown:

tshark reads the capture and extracts HTTP request URIs.

sort groups identical URI values together.

uniq -c counts consecutive identical lines.

sort -nr sorts the counts numerically in descending order.

Observed results:

A URI beginning with /pagead/ads?client=...&color_border=666633 appeared twice.

/download.html appeared twice.

Repeated requests are useful observations, but repetition alone does not establish malicious activity.

1.4 Extracting Source IP Addresses

The field ip.src extracts the source IP address from IP packets.

The source IP counts observed in the selected output were:

Source IP

Count

145.254.160.237

2

65.208.228.223

1

216.239.59.99

1

The counts depend on the packets selected by the display filter. Filtering HTTP requests and filtering all HTTP-related packets can produce different results.

1.5 Identifying HTTP Request Methods

The field http.request.method identifies the HTTP method, such as GET or POST.

The extracted method output contained two GET entries.

HTTP methods help describe the type of request being made. Their significance must be evaluated in the context of the surrounding traffic.

2. DNS Traffic Analysis

Capture file: dns.cap

2.1 Understanding DNS Fields

DNS fields use the dns. prefix.

The field dns.qry.name extracts the queried domain name.

DNS queries request information about a domain, while DNS responses provide answers or other DNS information. To focus on query packets, the display filter dns.flags.response == 0 can be used.

2.2 Extracting IPv4 Address Records

The field dns.a extracts IPv4 address records from DNS packets.

The following command was used to extract IPv4 answers:

tshark -r dns.cap -Y "dns.a" -T fields -e dns.a

The extracted output included these addresses:

216.239.37.26

64.233.167.25

66.102.9.25

216.239.57.25

216.239.57.26

204.152.190.12

204.152.184.88

Some output lines were blank because not every selected packet necessarily produced a value in the extracted field.

2.3 Extracting Domain Names and Address Answers Together

To examine the queried domain alongside the extracted IPv4 answers, both fields were selected:

tshark -r dns.cap -Y "dns.a" -T fields -e dns.qry.name -e dns.a

Observed associations:

Domain name

Extracted IPv4 address answer(s)

google.com

216.239.37.26, 64.233.167.25, 66.102.9.25, 216.239.57.25, 216.239.37.25, 216.239.57.26

www.netbsd.org

204.152.190.12

www.isc.org

204.152.184.88

These are the domain-to-address associations observed in the extracted output. The output alone does not establish why multiple addresses were returned or whether they all belonged to a single DNS response.

2.4 Understanding DNS Record Types

DNS responses can contain different types of information:

A: IPv4 address.

AAAA: IPv6 address.

CNAME: Alias pointing to another domain name.

MX: Mail server information.

TXT: Text information associated with a domain.

Therefore, a DNS response does not always simply provide an IP address. The type of query determines what information is requested, and the response may contain the corresponding record or other response information.

2.5 DNS Versus HTTP

DNS helps a client obtain information associated with a domain name, such as an IP address. HTTP or HTTPS is used to request web resources.

DNS does not itself deliver the website's page content.

When inspecting DNS packets in Wireshark, the query and response should be considered together. The source and destination IP addresses generally reverse direction between a request and its response.

3. Command-Line Concepts Learned

tshark -r: Reads a packet capture.

-Y: Filters packets using a display filter.

-T fields: Outputs selected fields.

-e: Specifies which field to extract.

ip.src: Extracts the source IP address.

http.request.uri: Extracts the HTTP request URI.

http.request.method: Extracts the HTTP request method.

dns.qry.name: Extracts the DNS queried domain name.

dns.a: Extracts IPv4 address records.

awk: Processes extracted text using conditions such as line length.

sort: Sorts lines and groups identical values together.

uniq -c: Counts consecutive identical lines.

sort -nr: Sorts numeric counts in descending order.

head -n 1: Displays the first line of the resulting output.

Important lessons

Extract protocol fields before processing packet data as text.

Use the correct field name for the protocol being investigated.

Apply filters carefully because they determine which packets are counted.

Interpret extracted values in context rather than assuming they are malicious.

Understand what each part of a command pipeline contributes to the result.

