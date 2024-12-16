const tls = require("node:tls");
const x509 = require("@peculiar/x509");
const sgx = require("@fleek-platform/sgx-quote-verify");

//const expected_mrenclave = new Uint8Array([
//  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
//  23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
//]);
let expected_mrenclave = Buffer.from(
  "b8afcbdc578fff975ef053e5b31480b92804e190a0c8c14b185ceab96c406016",
  "hex",
);

let host = "15.235.55.115";
let socket = tls.connect(
  {
    port: 8000,
    host,
    servername: host, // this is required in case the server enabled SNI
    rejectUnauthorized: false,
    requestCert: true,
  },
  () => {
    let cert = socket.getPeerX509Certificate();
    const b64 = Buffer.from(cert.raw).toString("base64");
    const x509_cert = new x509.X509Certificate(b64);

    socket.on("data", function(response) {
      console.log("response from server:");
      console.log(response);
    });

    for (let i = 0; i < x509_cert.extensions.length; i++) {
      let ext = x509_cert.extensions[i];
      if (ext.type == "1.1.1.1.1.1.69696.1.1") {
        let quote = Buffer.from(ext.value);

        const pccs_url = "pccs.fleek.network";
        sgx
          .verify(pccs_url, quote, "processor", expected_mrenclave)
          .then((res) => {
            if (res) {
              console.log("successful attestation");

              socket.setEncoding("utf8");
              socket.write(
                "GET /?prompt=If+its+a+significant+update+on+decentralized+AI+and+autonomous+agents. HTTP/1.1\r\nHost:www.example.com\r\n\r\n",
              );
              socket.read();
            }
          })
          .catch((err) => {
            console.error(err.message);
          });
      }
    }
  },
);
