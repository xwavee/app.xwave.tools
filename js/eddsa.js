!function(){
  // EdDSA implementation using Web Crypto API
  window.eddsa = window.eddsa || {};
  
  // Helper function to convert bytes to hex
  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  // Helper function to convert hex to bytes
  function hexToBytes(hex) {
    hex = hex.replace(/\s/g, '');
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }
  
  // Helper function to convert hex to PEM format
  function toPEM(hexKey, type) {
    const bytes = hexToBytes(hexKey);
    const base64 = btoa(String.fromCharCode.apply(null, bytes));
    const lines = base64.match(/.{1,64}/g) || [];
    return '-----BEGIN ' + type + '-----\n' + lines.join('\n') + '\n-----END ' + type + '-----';
  }
  
  // Helper function to extract hex from PEM format
  function fromPEM(pem) {
    const base64 = pem.replace(/-----BEGIN [A-Z ]+-----/, '')
                     .replace(/-----END [A-Z ]+-----/, '')
                     .replace(/\s/g, '');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytesToHex(bytes);
  }
  
  // Generate EdDSA key pair
  eddsa.generate = async function(keyType, pemFormat, cipherAlgorithm, passphraseEnabled, passphrase) {
    var output = $("#output");
    var publicKey = $("#public-key");
    var downloadPrivate = $("#download-image");
    var downloadPublic = $("#download-public");
    
    if (publicKey.length) {
      publicKey.val("");
    }
    
    // Get curve from page element (not passed as parameter)
    var curve = $('#curve').length ? $('#curve').val() : 'Ed25519';
    
    // Get keyType from page if not provided
    if (!keyType) {
      keyType = $('#key-type').length ? $('#key-type').val() : 'pem_text';
    }
    
    if (curve !== 'Ed25519') {
      var msg = "Currently only Ed25519 curve is supported.";
      if (output.length) {
        output.val(msg);
        if (downloadPrivate.length) {
          downloadPrivate.hide();
          downloadPublic.hide();
        }
      }
      return msg;
    }
    
    try {
      // Use Web Crypto API to generate Ed25519 key pair
      const keyPair = await crypto.subtle.generateKey(
        {
          name: "Ed25519",
        },
        true,
        ["sign", "verify"]
      );
      
      // Format output based on keyType (output format)
      let privateKeyOutput, publicKeyOutput;
      
      if (keyType === 'pem_text') {
        // PEM format - export as PKCS8/SPKI
        const privateKeyPKCS8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
        const publicKeySPKI = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        
        // Convert to base64
        const privateKeyBase64 = btoa(String.fromCharCode.apply(null, new Uint8Array(privateKeyPKCS8)));
        const publicKeyBase64 = btoa(String.fromCharCode.apply(null, new Uint8Array(publicKeySPKI)));
        
        // Format as PEM
        privateKeyOutput = '-----BEGIN PRIVATE KEY-----\n' + 
                          privateKeyBase64.match(/.{1,64}/g).join('\n') + 
                          '\n-----END PRIVATE KEY-----';
        publicKeyOutput = '-----BEGIN PUBLIC KEY-----\n' + 
                         publicKeyBase64.match(/.{1,64}/g).join('\n') + 
                         '\n-----END PUBLIC KEY-----';
        
        // Set download attributes
        if (downloadPrivate.length) {
          downloadPrivate.attr("href", "data:application/x-pem-file," + encodeURIComponent(privateKeyOutput));
          downloadPrivate.attr("download", "private.pem");
          downloadPublic.attr("href", "data:application/x-pem-file," + encodeURIComponent(publicKeyOutput));
          downloadPublic.attr("download", "public.pem");
          downloadPrivate.show();
          downloadPublic.show();
        }
        
      } else {
        // For hex and base64, extract raw key bytes
        const privateKeyRaw = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
        const publicKeyRaw = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        
        const privateKeyBytes = new Uint8Array(privateKeyRaw);
        const publicKeyBytes = new Uint8Array(publicKeyRaw);
        
        // Extract the 32-byte raw key from the encoded formats
        const privateKeyHex = bytesToHex(privateKeyBytes.slice(-32));
        const publicKeyHex = bytesToHex(publicKeyBytes.slice(-32));
        
        if (keyType === 'base64') {
          // Base64 format
          const privBytes = hexToBytes(privateKeyHex);
          const pubBytes = hexToBytes(publicKeyHex);
          privateKeyOutput = btoa(String.fromCharCode.apply(null, privBytes));
          publicKeyOutput = btoa(String.fromCharCode.apply(null, pubBytes));
        } else {
          // Hex format (default)
          privateKeyOutput = privateKeyHex;
          publicKeyOutput = publicKeyHex;
        }
        
        if (downloadPrivate.length) {
          downloadPrivate.hide();
          downloadPublic.hide();
        }
      }
      
      if (output.length) {
        output.val(privateKeyOutput);
      }
      if (publicKey.length) {
        publicKey.val(publicKeyOutput);
      }
      
      return privateKeyOutput;
      
    } catch(e) {
      // Fallback error message if Web Crypto API doesn't support Ed25519
      var errorMsg = "Error: Your browser does not support Ed25519 key generation.\n\n" +
                 "Ed25519 requires a modern browser (Chrome 113+, Firefox 119+, Safari 17+).\n\n" +
                 "For now, please use ECDSA with secp256k1 or secp256r1 curves as an alternative.\n\n" +
                 "Technical details: " + e.message;
      if (output.length) {
        output.val(errorMsg);
        if (publicKey.length) {
          publicKey.val("");
        }
        if (downloadPrivate.length) {
          downloadPrivate.hide();
          downloadPublic.hide();
        }
      }
      return errorMsg;
    }
  };
  
  // Sign message with EdDSA
  eddsa.sign = async function(message, inputType, privateKeyType, privateKey, passphrase) {
    // Get curve from page element
    var curve = $('#curve').length ? $('#curve').val() : 'Ed25519';
    
    if (curve !== 'Ed25519') {
      return "Currently only Ed25519 curve is supported.";
    }
    
    if (!message) {
      return "Please enter a message to sign.";
    }
    
    if (!privateKey) {
      return "Please enter a private key.";
    }
    
    try {
      let key;
      
      // Clean private key input
      privateKey = privateKey.replace(/\s/g, '');

      if (privateKeyType === 'pem_text') {
        // PEM format - import directly as PKCS8
        const pemContent = privateKey
          .replace(/-----BEGINPRIVATEKEY-----/, '')
          .replace(/-----ENDPRIVATEKEY-----/, '');
        
        const binaryString = atob(pemContent);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        
        key = await crypto.subtle.importKey(
          "pkcs8",
          bytes,
          {
            name: "Ed25519",
          },
          false,
          ["sign"]
        );
        
      } else {
        // Hex or Base64 format - convert to raw bytes first
        let privateKeyHex = privateKey;
        
        if (privateKeyType === 'base64') {
          const binaryString = atob(privateKey);
          const bytes = new Uint8Array(binaryString.length);
          for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
          }
          privateKeyHex = bytesToHex(bytes);
        }
        
        // Validate private key length (64 hex chars = 32 bytes)
        if (privateKeyHex.length !== 64) {
          return "Invalid private key length. Ed25519 private key must be 32 bytes (64 hex characters).";
        }
        
        // Convert hex to bytes and create PKCS8 format for import
        const privateKeyBytes = hexToBytes(privateKeyHex);
        
        // Create PKCS8 wrapper for raw Ed25519 private key
        const pkcs8Header = new Uint8Array([
          0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
          0x04, 0x22, 0x04, 0x20
        ]);
        const pkcs8Key = new Uint8Array(pkcs8Header.length + privateKeyBytes.length);
        pkcs8Key.set(pkcs8Header);
        pkcs8Key.set(privateKeyBytes, pkcs8Header.length);
        
        key = await crypto.subtle.importKey(
          "pkcs8",
          pkcs8Key,
          {
            name: "Ed25519",
          },
          false,
          ["sign"]
        );
      }
      
      
      // Sign the message
      let messageBytes;
      if (inputType === 'hex') {
        messageBytes = hexToBytes(message);
      } else if (inputType === 'base64') {
        const binaryString = atob(message);
        messageBytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          messageBytes[i] = binaryString.charCodeAt(i);
        }
      } else {
        // Default text (UTF-8)
        messageBytes = new TextEncoder().encode(message);
      }
      
      const signatureBytes = await crypto.subtle.sign(
        {
          name: "Ed25519",
        },
        key,
        messageBytes
      );
      
      // Convert signature to hex
      const signatureHex = bytesToHex(new Uint8Array(signatureBytes));
      
      return signatureHex;
      
    } catch(e) {
      return "Error signing message: " + e.message + "\n\nYour browser may not fully support Ed25519.";
    }
  };
  
  // Verify EdDSA signature
  eddsa.verify = async function(message, inputType, publicKeyType, pubKey, signatureType, signature) {
    var output = $("#output");
    
    // Get curve from page element
    var curve = $('#curve').length ? $('#curve').val() : 'Ed25519';
    
    if (curve !== 'Ed25519') {
      const msg = "Currently only Ed25519 curve is supported.";
      if (output.length) {
        output.val(msg);
      }
      return msg;
    }
    
    if (!message) {
      const msg = "Please enter a message to verify.";
      if (output.length) {
        output.val(msg);
      }
      return msg;
    }
    
    if (!pubKey) {
      const msg = "Public key is blank";
      if (output.length) {
        output.val(msg);
      }
      return msg;
    }
    
    if (!signature) {
      const msg = "Signature is blank";
      if (output.length) {
        output.val(msg);
      }
      return msg;
    }
    
    try {
      let key;
      
      // Clean inputs
      pubKey = pubKey.replace(/\s/g, '');
      signature = signature.replace(/\s/g, '');
      
      if (publicKeyType === 'pem_text') {
        // PEM format - import directly as SPKI
        const pemContent = pubKey
          .replace(/-----BEGINPUBLICKEY-----/, '')
          .replace(/-----ENDPUBLICKEY-----/, '');
        
        const binaryString = atob(pemContent);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        
        key = await crypto.subtle.importKey(
          "spki",
          bytes,
          {
            name: "Ed25519",
          },
          false,
          ["verify"]
        );
        
      } else {
        // Hex or Base64 format - convert to raw bytes first
        let publicKeyHex = pubKey;
        
        if (publicKeyType === 'base64') {
          const binaryString = atob(pubKey);
          const bytes = new Uint8Array(binaryString.length);
          for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
          }
          publicKeyHex = bytesToHex(bytes);
        }
        
        // Validate public key length
        if (publicKeyHex.length !== 64) {
          const msg = "Invalid public key length. Ed25519 public key must be 32 bytes (64 hex characters).";
          if (output.length) {
            output.val(msg);
          }
          return msg;
        }
        
        // Convert to bytes and create SPKI format for import
        const publicKeyBytes = hexToBytes(publicKeyHex);
        
        // Create SPKI wrapper for raw Ed25519 public key
        const spkiHeader = new Uint8Array([
          0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
        ]);
        const spkiKey = new Uint8Array(spkiHeader.length + publicKeyBytes.length);
        spkiKey.set(spkiHeader);
        spkiKey.set(publicKeyBytes, spkiHeader.length);
        
        key = await crypto.subtle.importKey(
          "spki",
          spkiKey,
          {
            name: "Ed25519",
          },
          false,
          ["verify"]
        );
      }
      
      // Parse signature
      let signatureHex = signature;
      if (signatureType === 'base64') {
        const binary = atob(signature);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }
        signatureHex = bytesToHex(bytes);
      }
      
      // Validate signature length
      if (signatureHex.length !== 128) {
        const msg = "Invalid signature length. Ed25519 signature must be 64 bytes (128 hex characters).";
        if (output.length) {
          output.val(msg);
        }
        return msg;
      }
      
      // Verify signature
      const signatureBytes = hexToBytes(signatureHex);
      
      let messageBytes;
      if (inputType === 'hex') {
        messageBytes = hexToBytes(message);
      } else if (inputType === 'base64') {
        const binaryString = atob(message);
        messageBytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          messageBytes[i] = binaryString.charCodeAt(i);
        }
      } else {
        // Default text (UTF-8)
        messageBytes = new TextEncoder().encode(message);
      }
      
      const isValid = await crypto.subtle.verify(
        {
          name: "Ed25519",
        },
        key,
        signatureBytes,
        messageBytes
      );
      
      const result = isValid ? "Valid" : "Signature is invalid";
      
      if (output.length) {
        output.val(result);
      }
      
      return result;
      
    } catch(e) {
      const errorMsg = "Error verifying signature: " + e.message;
      
      if (output.length) {
        output.val(errorMsg);
      }
      
      return errorMsg;
    }
  };
  
}();
