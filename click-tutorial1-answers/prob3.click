// input packet encapsulation is IP

// declarations
fd :: FromDump("f3a.dump", STOP true);
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
tdb :: ToDump("f3b.dump", 0, IP);
tdc :: ToDump("f3c.dump", 0, IP);
tdd :: ToDump("f3d.dump", 0, IP);
tde :: ToDump("f3e.dump", 0, IP);
tdf :: ToDump("f3f.dump", 0, IP);
icmperror :: ICMPError(0.0.0.0, 11);

fd -> chkip -> ipclass0 -> chktcp;
ipclass0[1] -> chkudp;
ipclass0[2] -> chkicmp;
chktcp, chkudp, chkicmp, ipclass0[3] -> ipclass1[0, 1] -> icmperror -> tdf;
ipclass1[2] -> chklen -> rt => tdb, tdc, tdd, tde;
//Script(print "ok",stop);
