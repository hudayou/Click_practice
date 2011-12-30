// input packet encapsulation is IP

// declarations
elementclass ErrorChecker {
rt :: LinearIPLookup(131.0.0.0/8 0,
                     131.179.0.0/16 1,
                     18.0.0.0/8 2,
                     0/0 3);
chkip :: CheckIPHeader;
ipclass0 :: IPClassifier(tcp, udp, icmp, -);
ipclass1 :: IPClassifier(ip ttl 0, ip ttl 1, -);
chklen :: CheckLength(1500);
chktcp :: CheckTCPHeader;
chkudp :: CheckUDPHeader;
chkicmp :: CheckICMPHeader;
icmperror :: ICMPError(0.0.0.0, 11);
discard :: Discard;

input-> chkip -> ipclass0 -> chktcp;
ipclass0[1] -> chkudp;
ipclass0[2] -> chkicmp;
chktcp, chkudp, chkicmp, ipclass0[3] -> ipclass1[0, 1] -> icmperror -> discard;
ipclass1[2] -> chklen -> rt -> output;
||
rt :: LinearIPLookup(131.0.0.0/8 0,
                     131.179.0.0/16 1,
                     18.0.0.0/8 2,
                     0/0 3);
chkip :: CheckIPHeader;
ipclass0 :: IPClassifier(tcp, udp, icmp, -);
ipclass1 :: IPClassifier(ip ttl 0, ip ttl 1, -);
chklen :: CheckLength(1500);
chktcp :: CheckTCPHeader;
chkudp :: CheckUDPHeader;
chkicmp :: CheckICMPHeader;
icmperror :: ICMPError(0.0.0.0, 11);
discard :: Discard;

input-> chkip -> ipclass0 -> chktcp;
ipclass0[1] -> chkudp;
ipclass0[2] -> chkicmp;
chktcp, chkudp, chkicmp, ipclass0[3] -> ipclass1[0, 1] -> icmperror;
ipclass1[2] -> chklen -> rt -> output;
chkip[1], chktcp[1], chkudp[1], chkicmp[1], icmperror, chklen[1]  ->
[1]output;
||
rt :: LinearIPLookup(131.0.0.0/8 0,
                     131.179.0.0/16 1,
                     18.0.0.0/8 2,
                     0/0 3);
chkip :: CheckIPHeader;
ipclass0 :: IPClassifier(tcp, udp, icmp, -);
ipclass1 :: IPClassifier(ip ttl 0, ip ttl 1, -);
chklen :: CheckLength(1500);
chktcp :: CheckTCPHeader;
chkudp :: CheckUDPHeader;
chkicmp :: CheckICMPHeader;
icmperror :: ICMPError(0.0.0.0, 11);
discard :: Discard;

input-> chkip -> ipclass0 -> chktcp;
ipclass0[1] -> chkudp;
ipclass0[2] -> chkicmp;
chktcp, chkudp, chkicmp, ipclass0[3] -> ipclass1[0, 1] -> icmperror;
ipclass1[2] -> chklen -> rt -> output;
chkip[1], chktcp[1], chkudp[1], chkicmp[1], icmperror, chklen[1]  =>
[1,2,3,4,5,6]output;
}
