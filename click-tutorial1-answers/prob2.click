fd :: FromDump("f2a.dump");
rt :: LinearIPLookup(131.0.0.0/8 0,
                     131.179.0.0/16 1,
                     18.0.0.0/8 2,
                     0/0 3);
td0 :: ToDump("f2b.dump", , IP);
td1 :: ToDump("f2c.dump", 0, IP);
td2 :: ToDump("f2d.dump", 0, IP);
td3 :: ToDump("f2e.dump", 0, IP);
fd -> rt;
rt => td0, td1, td2, td3;
Script(print $(fd.encap),stop);
