DECLARE
   --------------------------------------------------------------------------------------- 
   -- AES256-CBC interoperability check: 
   --   => OracleATP => Web Crypto API (JS) => Golang => Java => Python =>
   -- Friedhold Matz : 31-01.2021
   -----------------------------------
   -- Outputs, check on OracleATP 21c:
   -- ................................
   -- Original string: `Hello, World!`  
   -- Key-Bytes-Raw   : 3132333435363738313233343536373831323334353637383132333435363738
   -- IV-Bytes-Raw    : 31323334353637383132333435363738
   -- Encrypted-Raw   : 01EB8015F319BDA885939D265C4A38A0
   -- Decrypted string: Hello, World!
   ----------------------------------------------------------------------------------------
   input_string       VARCHAR2 (200) := 'Hello, World!';
   output_string      VARCHAR2 (200);
   encrypted_raw      RAW (2000);       -- stores encrypted binary text
   decrypted_raw      RAW (2000);       -- stores decrypted binary text
   num_key_bytes      NUMBER := 256/8;  -- key length 256 bits (32 bytes)
   key_bytes_raw      RAW (32);         -- stores 256-bit encryption key 
   encryption_type    PLS_INTEGER :=    -- total encryption type
                        SYS.DBMS_CRYPTO.ENCRYPT_AES256
                        + DBMS_CRYPTO.CHAIN_CBC
                        + DBMS_CRYPTO.PAD_PKCS5;
   iv_bytes_raw       RAW (16);
   
BEGIN
   DBMS_OUTPUT.PUT_LINE ('Original string: ' || input_string);
   key_bytes_raw := DBMS_CRYPTO.RANDOMBYTES (num_key_bytes);
    
   key_bytes_raw := UTL_RAW.CAST_TO_RAW('12345678123456781234567812345678');    
   DBMS_OUTPUT.PUT_LINE ('Key-Bytes-Raw: ' || key_bytes_raw );  -- 32 Bytes
   
   iv_bytes_raw := UTL_RAW.CAST_TO_RAW('1234567812345678');    
   DBMS_OUTPUT.PUT_LINE ('IV-Bytes-Raw:  ' || iv_bytes_raw );  -- 16 Bytes
    
   encrypted_raw := DBMS_CRYPTO.ENCRYPT (
         src => UTL_I18N.STRING_TO_RAW (input_string, 'AL32UTF8'),
         typ => encryption_type,
         key => key_bytes_raw,
         iv  => iv_bytes_raw
   );
    
   -- The encrypted value in the encrypted_raw variable can be used here
    
   DBMS_OUTPUT.PUT_LINE ( 'Encrypted-Raw: ' || encrypted_raw );
    
   decrypted_raw := DBMS_CRYPTO.DECRYPT (
         src => encrypted_raw,
         typ => encryption_type,
         key => key_bytes_raw,
         iv  => iv_bytes_raw 
   );
   output_string := UTL_I18N.RAW_TO_CHAR (decrypted_raw, 'AL32UTF8');
   DBMS_OUTPUT.PUT_LINE ('Decrypted string: ' || output_string);

END "OATP-AES256";
