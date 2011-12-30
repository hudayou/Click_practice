fd :: FromDump("f1a.dump");
td :: ToDump("f1b.dump", 0, IP);
fd -> td;
Script(print $(fd.encap),stop);
