// input packet encapsulation is IP

// declarations
fd :: FromDump("f4a.dump");
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
tdb :: ToDump("f4b.dump", 0, IP);
tdc :: ToDump("f4c.dump", 0, IP);
tdd :: ToDump("f4d.dump", 0, IP);
tde :: ToDump("f4e.dump", 0, IP);
tdf :: ToDump("f4f.dump", 0, IP);
icmperror :: ICMPError(0.0.0.0, 11);
discard :: Discard;

fd -> chkip -> ipclass0 -> chktcp;
ipclass0[1] -> chkudp;
ipclass0[2] -> chkicmp;
chktcp, chkudp, chkicmp, ipclass0[3] -> ipclass1[0, 1] -> icmperror -> tdf;
ipclass1[2] -> chklen -> rt => tdb, tdc, tdd, tde;
chklen[1] -> discard;
Script(print > f4.drops chkip.drops,
       print >> f4.drops chktcp.drops,
       print >> f4.drops chkudp.drops,
       print >> f4.drops chkicmp.drops,
       print >> f4.drops tdf.count,
       print >> f4.drops discard.count,
       stop);
