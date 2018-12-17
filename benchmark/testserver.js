const dgram=require("dgram");
const server=dgram.createSocket("udp4");

const PORT=3333;

server.on("message",(msg,rinfo)=>{
    console.log(`${msg}`);
    server.send(Buffer.from("OK"),rinfo.port,rinfo.address);
});

server.on("listening",()=>{
    const address=server.address();
    console.log(`Listening ${address.address}:${address.port}`);
});

server.bind(PORT);