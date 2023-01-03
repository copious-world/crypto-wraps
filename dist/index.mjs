const e=["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9","+","/"],r=["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9","-","_"],t=[255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,62,255,255,255,63,52,53,54,55,56,57,58,59,60,61,255,255,255,0,255,255,255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,255,255,255,255,255,255,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51],n="-_".charCodeAt(0),i="-_".charCodeAt(1);function a(e){if(n===e)return 62;if(i===e)return 63;if(e>=t.length)throw new Error("Unable to parse base64 string.");const r=t[e];if(255===r)throw new Error("Unable to parse base64 string.");return r}function o(e){for(;e.length%4;)e+="=";return function(e){if(e.length%4!=0)throw new Error("Unable to parse base64 string.");const r=e.indexOf("=");if(-1!==r&&r<e.length-2)throw new Error("Unable to parse base64 string.");let t,n=e.endsWith("==")?2:e.endsWith("=")?1:0,i=e.length,o=new Uint8Array(i/4*3);for(let r=0,n=0;r<i;r+=4,n+=3)t=a(e.charCodeAt(r))<<18|a(e.charCodeAt(r+1))<<12|a(e.charCodeAt(r+2))<<6|a(e.charCodeAt(r+3)),o[n]=t>>16,o[n+1]=t>>8&255,o[n+2]=255&t;return o.subarray(0,o.length-n)}(e)}function c(t){let n=function(t,n){let i,a=n?e:r,o="",c=t.length;for(i=2;i<c;i+=3)o+=a[t[i-2]>>2],o+=a[(3&t[i-2])<<4|t[i-1]>>4],o+=a[(15&t[i-1])<<2|t[i]>>6],o+=a[63&t[i]];return i===c+1&&(o+=a[t[i-2]>>2],o+=a[(3&t[i-2])<<4],o+="=="),i===c&&(o+=a[t[i-2]>>2],o+=a[(3&t[i-2])<<4|t[i-1]>>4],o+=a[(15&t[i-1])<<2],o+="="),o}(t);return n=n.replace(/\=/g,""),n}function y(e){if(void 0===e){return c(window.crypto.getRandomValues(new Uint8Array(16)))}{let r=o(e);return r=r.subarray(0,16),c(r)}}async function w(){try{return g_crypto.generateKey({name:"AES-CBC",length:256},!0,["encrypt","decrypt"])}catch(e){}return!1}function p(){return g_crypto.generateKey({name:"ECDSA",namedCurve:"P-384"},!0,["sign","verify"])}function s(){return g_crypto.generateKey({name:"ECDH",namedCurve:"P-384"},!0,["deriveKey"])}function u(){return g_crypto.generateKey({name:"RSA-OAEP",modulusLength:4096,publicExponent:new Uint8Array([1,0,1]),hash:{name:"SHA-256"}},!0,["wrapKey","unwrapKey"])}async function _(e,r,t){let n=!1;if("string"==typeof e){n=(new TextEncoder).encode(e)}else"Uint8Array"!==e.constructor.name&&"Buffer"!==e.constructor.name||(n=e);if(n){let e=t;return await g_crypto.encrypt({name:"AES-CBC",iv:e},r,n)}return!1}async function d(e,r,t){let n=t,i=await g_crypto.decrypt({name:"AES-CBC",iv:n},r,e);return(new TextDecoder).decode(i)}async function l(e){let r=!1,t=!1;if(void 0===e||"wrapper"===e){let e=await u(),n=e.publicKey,i=e.privateKey,a=await g_crypto.exportKey("jwk",n);r=JSON.stringify(a);let o=await g_crypto.exportKey("jwk",i);t=JSON.stringify(o)}let n=!1,i=!1;if(void 0===e||"signer"===e){let e=await p(),r=e.publicKey,t=e.privateKey,a=await g_crypto.exportKey("jwk",r);n=JSON.stringify(a);let o=await g_crypto.exportKey("jwk",t);i=JSON.stringify(o)}let a=!1,o=!1;if(void 0===e||"derive"===e){let e=await s(),r=e.publicKey,t=e.privateKey,n=await g_crypto.exportKey("jwk",r);a=JSON.stringify(n);let i=await g_crypto.exportKey("jwk",t);o=JSON.stringify(i)}let c={pk_str:r,priv_key:t,signer_pk_str:n,signer_priv_key:i,axiom_pk_str:a,axiom_priv_key:o};return!1===c.pk_str&&(delete c.pk_str,delete c.priv_key),!1===c.signer_pk_str&&(delete c.signer_pk_str,delete c.signer_priv_key),!1===c.axiom_pk_str&&(delete c.axiom_pk_str,delete c.axiom_priv_key),c}async function g(e){return await l(e)}async function m(e,r,t,n){try{let i=e.signer_priv_key,a=await j(n,i),y=o(t),w=await _(a,r,y);return c(new Uint8Array(w))}catch(e){return console.log(e),!1}}async function f(e,r,t,n,i){try{let a=t.signer_pk_str,c=o(i),y=await o(r),w=await g_crypto.decrypt({name:"AES-CBC",iv:c},n,y);let p=(new TextDecoder).decode(w);return await O(e,p,a)}catch(e){console.log(e)}return!1}async function k(e,r){return await g_crypto.unwrapKey("jwk",e,r,{name:"RSA-OAEP",modulusLength:4096,publicExponent:new Uint8Array([1,0,1]),hash:{name:"SHA-256"}},{name:"AES-CBC",length:256},!0,["encrypt","decrypt"])}async function h(e,r){return await g_crypto.deriveKey({name:"ECDH",public:e},r,{name:"AES-CBC",length:256},!1,["encrypt","decrypt"])}async function v(e,r){try{let t=JSON.parse(r),n=await g_crypto.importKey("jwk",t,{name:"RSA-OAEP",modulusLength:4096,publicExponent:new Uint8Array([1,0,1]),hash:{name:"SHA-256"}},!0,["wrapKey"]),i=await g_crypto.wrapKey("jwk",e,n,{name:"RSA-OAEP"});return c(new Uint8Array(i))}catch(e){console.log(e)}return!1}async function A(e,r){let t=JSON.parse(r),n=await g_crypto.importKey("jwk",t,{name:"RSA-OAEP",modulusLength:4096,publicExponent:new Uint8Array([1,0,1]),hash:{name:"SHA-256"}},!0,["unwrapKey"]),i=o(e);return await k(i,n)}async function K(e,r){let t=JSON.parse(r),n=await g_crypto.importKey("jwk",t,{name:"ECDH",namedCurve:"P-384"},!0,["deriveKey"]),i=o(e);return await h(i,n)}async function S(e,r){if("jwk"===r){const r=await g_crypto.exportKey("jwk",e);return JSON.stringify(r)}{const r=await g_crypto.exportKey("raw",e);return c(new Uint8Array(r))}}async function C(e,r){if("jwk"===r){const r=await g_crypto.exportKey("jwk",e);return r.key_ops=["deriveKey"],JSON.stringify(r)}{const r=await g_crypto.exportKey("raw",e);return c(new Uint8Array(r))}}function E(e,r){return g_crypto.importKey(r,e,{name:"AES-CBC",length:256},!0,["encrypt","decrypt"])}function x(e,r){return"string"==typeof e&&(e=JSON.parse(e)),"jwk"===r&&(void 0===e.key_ops||Array.isArray(e.key_ops)&&0===e.key_ops.length)&&(e.key_ops=["deriveKey"]),g_crypto.importKey(r,e,{name:"ECDH",namedCurve:"P-384"},!0,["deriveKey"])}async function b(e,r){if("jwk"!==r){let r=o(e);return await E(r,"raw")}try{let r=JSON.parse(e);return await E(r,"jwk")}catch(e){}}async function j(e,r){try{let t=JSON.parse(r),n=await g_crypto.importKey("jwk",t,{name:"ECDSA",namedCurve:"P-384"},!0,["sign"]),i=(new TextEncoder).encode(e),a=await g_crypto.sign({name:"ECDSA",hash:{name:"SHA-384"}},n,i);return c(new Uint8Array(a))}catch(e){console.log(e)}return!1}async function O(e,r,t){try{let n=JSON.parse(t),i=await g_crypto.importKey("jwk",n,{name:"ECDSA",namedCurve:"P-384"},!0,["verify"]),a=(new TextEncoder).encode(e),c=o(r);return await g_crypto.verify({name:"ECDSA",hash:{name:"SHA-384"}},i,c,a)}catch(e){console.log(e)}return!1}async function N(e,r,t,n){try{if(r){let i=o(t),a=await _(e,r,i),y=new Uint8Array(a);return n?y:c(y)}}catch(e){console.log(e)}return!1}async function U(e,r,t,n){try{if(r&&t){let i=await h(r,t),a=o(n),y=await _(e,i,a);return c(new Uint8Array(y))}}catch(e){console.log(e)}return!1}async function J(e,r,t,n){try{let i=await A(r,t);if(i){let r=o(n),t=o(e);return await d(t,i,r)}}catch(e){console.log(e)}return!1}async function D(e,r,t,n){try{let i=await K(r,t);if(i){let r=o(n),t=o(e);return await d(t,i,r)}}catch(e){console.log(e)}return!1}async function H(e,r){let t=JSON.parse(e),n=await g_crypto.importKey("jwk",t,{name:"ECDH",namedCurve:"P-384"},!0,["deriveKey"]),i=JSON.parse(r),a=await g_crypto.importKey("jwk",i,{name:"ECDH",namedCurve:"P-384"},!0,["deriveKey"]);return await h(n,a)}async function P(e,r,t,n){try{let i=await H(r,t);if(i){let r=o(n),t=o(e);return await d(t,i,r)}}catch(e){console.log(e)}return!1}async function B(e,r){let t=await l();e.public_key=t.pk_str,e.signer_public_key=t.signer_pk_str,e.axiom_public_key=t.axiom_pk_str;let n=await w(),i=await S(n),a=y(),o={priv_key:t.priv_key,signer_priv_key:t.signer_priv_key,axiom_priv_key:t.axiom_priv_key,signature_protect:{key:i,nonce:a}};e.biometric=await m(o,n,a,e.biometric),r&&r(e,o)}function T(){window.gen_nonce=y,window.gen_cipher_key=w,window.keypair_promise=p,window.axiom_keypair_promise=s,window.wrapper_keypair_promise=u,window.aes_encryptor=_,window.aes_decipher_message=d,window.asymmetric_starter_keys=g,window.galactic_user_starter_keys=l,window.protect_hash=m,window.verify_protected=f,window.unwrapped_aes_key=k,window.derive_aes_key=h,window.derive_key_jwk=H,window.key_wrapper=v,window.key_unwrapper=A,window.derive_key=K,window.aes_to_str=S,window.ecdh_to_str=C,window.importAESKey=E,window.importECDHKey=x,window.aes_from_str=b,window.key_signer=j,window.verifier=O,window.encipher_message=N,window.derived_encipher_message=U,window.decipher_message=J,window.derived_decipher_message=D,window.derived_decipher_message_jwk=P,window.gen_public_key=B}void 0===window.g_crypto&&(window.g_crypto=window.crypto?window.crypto.subtle:null,null===g_crypto&&alert("No cryptography support in this browser. To claim ownership of assets, please use another browser.")),void 0===window.g_crypto&&(window.g_crypto=window.crypto?window.crypto.subtle:null,null===g_crypto&&alert("No cryptography support in this browser. To claim ownership of assets, please use another browser."));export{d as aes_decipher_message,_ as aes_encryptor,b as aes_from_str,S as aes_to_str,g as asymmetric_starter_keys,s as axiom_keypair_promise,J as decipher_message,h as derive_aes_key,K as derive_key,H as derive_key_jwk,D as derived_decipher_message,P as derived_decipher_message_jwk,U as derived_encipher_message,C as ecdh_to_str,N as encipher_message,l as galactic_user_starter_keys,w as gen_cipher_key,y as gen_nonce,B as gen_public_key,E as importAESKey,x as importECDHKey,j as key_signer,A as key_unwrapper,v as key_wrapper,p as keypair_promise,m as protect_hash,k as unwrapped_aes_key,O as verifier,f as verify_protected,T as windowize_crypto_wraps,u as wrapper_keypair_promise};
