### NewKey Serial Protocol

1. input protocol

    param | length | value 
    ---|---|---
    begin magic | 1 byte        | 0x88
    version     | 1 byte        | 0x01
    opcode      | 1 byte        | 
    param1      | 1 byte        |
    param2      | 2 byte        |
    data        | n bytes       |
    pad         | up to 96 byte | 0x00
    end magic   | 1 byte        | 0x99
    crc16       | 2 byte        | 
    
2. output protocol
    
    param | length | value 
    ---|---|---
    begin magic | 1 byte        | 0x88
    version     | 1 byte        | 0x01
    result      | 1 byte        |
    data        | n bytes       |
    pad         | up to 96 byte | 0x00
    end magic   | 1 byte        | 0x99
    crc16       | 2 byte        | 

### Commands

1. change password

    input:
    
    param | length | value 
    ---|---|---
    begin magic | 1 byte | 0x88
    version     | 1 byte | 0x01
    opcode      | 1 byte | 0x12
    param1      | 1 byte | 0x00
    param2      | 2 byte | 0x00 0x00
    old password        | 32 byte| 
    new password        | 32 byte| 
    pad         | up to 96 bytes | 0x00
    end magic   | 1 byte | 0x99
    crc16       | 2 byte        | 
    
    output:
    
    param | length | value 
    ---|---|---
    begin magic | 1 byte | 0x88
    version     | 1 byte | 0x01
    result      | 1 byte | 0x00
    pad         | up to 96 byte| 0x00
    end magic   | 1 byte | 0x99
    crc16       | 2 byte        | 
    
2. write private key.

    input:
    
    param | length | value 
    ---|---|---
    begin magic | 1 byte | 0x88
    version     | 1 byte | 0x01
    opcode      | 1 byte | 0x46
    param1      | 1 byte | 0x00
    param2      | 2 byte | 0x00 0x00
    password        | 32 byte| 
    private key     | 32 byte| 
    pad         | up to 96 bytes | 0x00
    end magic   | 1 byte | 0x99
    crc16       | 2 byte        | 
    
    output:
    
    param | length | value 
    ---|---|---
    begin magic | 1 byte | 0x88
    version     | 1 byte | 0x01
    result      | 1 byte |
    pad         | up to 96 byte| 0x00
    end magic   | 1 byte | 0x99
    crc16       | 2 byte        | 
    

3. get public key from existing private key.

    input:
    
    param | length | value 
    ---|---|---
    begin magic | 1 byte | 0x88
    version     | 1 byte | 0x01
    opcode      | 1 byte | 0x40
    param1      | 1 byte | 0x00
    param2      | 2 byte | 0x00 0x00
    password    | 32 byte| 
    pad         | up to 96 byte| 0x00
    end magic   | 1 byte | 0x99
    crc16       | 2 byte        | 
    
    output:
    
    param | length | value 
    ---|---|---
    begin magic | 1 byte | 0x88
    version     | 1 byte | 0x01
    result      | 1 byte |
    data        | 64 byte| public key
    pad         | up to 96 byte| 0x00
    end magic   | 1 byte | 0x99
    crc16       | 2 byte        | 

4. sign 32 byte hash data and return sign data.

    input:
    
    param | length | value 
    ---|---|---
    begin magic | 1 byte | 0x88
    version     | 1 byte | 0x01
    opcode      | 1 byte | 0x41
    param1      | 1 byte | 0x80
    param2      | 2 byte | 0x00 0x00
    password    | 32 byte| 
    data        | 32 byte| hash data
    pad         | up to 96 byte| 0x00
    end magic   | 1 byte | 0x99
    crc16       | 2 byte        | 
    
    output:
    
    param | length | value 
    ---|---|---
    begin magic | 1 byte | 0x88
    version     | 1 byte | 0x01
    result      | 1 byte |
    data        | 64 byte| sign data
    pad         | up to 96 byte| 0x00
    end magic   | 1 byte | 0x99
    crc16       | 2 byte        | 
    
5. get device serial number.

    input:
    
    param | length | value 
    ---|---|---
    begin magic | 1 byte | 0x88
    version     | 1 byte | 0x01
    opcode      | 1 byte | 0x02
    param1      | 1 byte | 0x80
    param2      | 2 byte | 0x00 0x00
    pad         | up to 96 byte| 0x00
    end magic   | 1 byte | 0x99
    crc16       | 2 byte        | 
    
    output:
    
    param | length | value 
    ---|---|---
    begin magic | 1 byte | 0x88
    version     | 1 byte | 0x01
    result      | 1 byte |
    data        | 9 byte| serial number
    pad         | up to 96 byte| 0x00
    end magic   | 1 byte | 0x99
    crc16       | 2 byte        | 

6. initiate session. after this command, protocol will be encrypted with AES.

    input:
    
    param | length | value 
    ---|---|---
    begin magic | 1 byte | 0x88
    version     | 1 byte | 0x01
    opcode      | 1 byte | 0x01
    param1      | 1 byte | 0x00
    param2      | 2 byte | 0x00 0x00
    pad         | up to 96 byte| 0x00
    end magic   | 1 byte | 0x99
    crc16       | 2 byte        | 
    
    output:
    
    param | length | value 
    ---|---|---
    begin magic | 1 byte | 0x88
    version     | 1 byte | 0x01
    result      | 1 byte |
    data        | 0 byte | 0x00
    pad         | up to 96 byte| 0x00
    end magic   | 1 byte | 0x99
    crc16       | 2 byte        | 


