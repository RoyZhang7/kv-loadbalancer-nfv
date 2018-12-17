const dgram=require("dgram");

const CONFIG=require("./config.json");

const socket=dgram.createSocket("udp4");

const HOST=CONFIG.host;
const PORT=CONFIG.port;

//
//
let f_total=0;
//
const keys=CONFIG.keys;
for(let i=0;i<keys.length;i++){
    f_total+=keys[i].frequency;
}
//
let keys_freq_table=[];
let f_cnt=0;
for(let i=0;i<keys.length;i++){
    let k=keys[i];

    let floor=f_cnt/f_total;
    f_cnt+=k.frequency;
    let ceiling=f_cnt/f_total;

    keys_freq_table.push({
        key:k.key,
        floor:floor,
        ceiling:ceiling
    });
}

//
//send request
const MAX_REQ_CNT=1000;
let req_cnt=0;

let req_total=0;

let key_cnt={};
for(let i=0;i<keys_freq_table.length;i++){
    let key=keys_freq_table[i].key;
    key_cnt[key]=0;
}

function req(){
    //
    let key;
    let r=Math.random();
    for(let i=0;i<keys_freq_table.length;i++){
        let k=keys_freq_table[i];
        if(r>=k.floor && r<=k.ceiling){
            key=k.key;
            key_cnt[key]++;
        }else{
            continue;
        }
    }
    if(!key){
        return;
    }

    req_cnt++;
    socket.send(
        Buffer.from(key),
        PORT,
        HOST,
        (err)=>{
            req_cnt--;
            req_total++;
            req();
        }
    );
    if(req_cnt<MAX_REQ_CNT){
        req();
    }
}
req();

//
//print statistics
sec=0;
setInterval(()=>{
    sec++;
    console.log(`${req_total} requests sent in ${sec} seconds`);
    console.log(`${Math.floor(req_total/sec)} requests per second`);
    for(let key in key_cnt){
        console.log(key, key_cnt[key]);
    }
    console.log();
},1000);

//
//get response from server
socket.on("message",(msg,rinfo)=>{
});
