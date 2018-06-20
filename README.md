### operate atecc508a over serial port

## protocol

1. input protocol

    param | length | value
    ---|---|---
    begin magic | 1 byte | 0x88
    data length | 1 byte | 1 + 1 + 1 + 2 + n + 1
    opcode      | 1 byte |
    param1      | 1 byte |
    param2      | 2 byte |
    data        | n byte |
    end magic   | 1 byte | 0x99
    pad         | total 64 byte| 0x00

2. output protocol

    param | length | value
    ---|---|---
    begin magic | 1 byte | 0x88
    data length | 1 byte | 1 + n + 1
    result      | n byte |
    end magic   | 1 byte | 0x99
    pad         | total 96 byte| 0x00

3. generate new private key and get public key.

    input:

    param | length | value
    ---|---|---
    begin magic | 1 byte | 0x88
    data length | 1 byte | 0x06
    opcode      | 1 byte | 0x40
    param1      | 1 byte | 0x04
    param2      | 2 byte | 0x00 0x00
    end magic   | 1 byte | 0x99

    example:
    88064004000099000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

    success output:

    param | length | value
    ---|---|---
    begin magic | 1 byte | 0x88
    data length | 1 byte | 0x42
    result        | 64 byte | public key
    end magic   | 1 byte | 0x99

    error output:

    param | length | value
    ---|---|---
    begin magic | 1 byte | 0x88
    data length | 1 byte | 0x03
    result      | 1 byte | error code
    end magic   | 1 byte | 0x99


4. get public key from existing private key.

    input:

    param | length | value
    ---|---|---
    begin magic | 1 byte | 0x88
    data length | 1 byte | 0x06
    opcode      | 1 byte | 0x40
    param1      | 1 byte | 0x00
    param2      | 2 byte | 0x00 0x00
    end magic   | 1 byte | 0x99

    example:
    88064000000099000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

    success output:

    param | length | value
    ---|---|---
    begin magic | 1 byte | 0x88
    data length | 1 byte | 0x42
    result      | 64 byte | public key
    end magic   | 1 byte | 0x99

    error output:

    param | length | value
    ---|---|---
    begin magic | 1 byte | 0x88
    data length | 1 byte | 0x03
    result      | 1 byte | error code
    end magic   | 1 byte | 0x99


5. sign 32 byte hash data and return sign data.

    input:

    param | length | value
    ---|---|---
    begin magic | 1 byte | 0x88
    data length | 1 byte | 0x26
    opcode      | 1 byte | 0x41
    param1      | 1 byte | 0x80
    param2      | 2 byte | 0x00 0x00
    data        | 32 byte| hash data
    end magic   | 1 byte | 0x99

    example:
    88264180000001020102010201020102010201020102010201020102010201020102010201029900000000000000000000000000000000000000000000000000

    success output:

    param | length | value
    ---|---|---
    begin magic | 1 byte | 0x88
    data length | 1 byte | 0x42
    result      | 64 byte | sign data
    end magic   | 1 byte | 0x99

    error output:

    param | length | value
    ---|---|---
    begin magic | 1 byte | 0x88
    data length | 1 byte | 0x03
    result      | 1 byte | error code
    end magic   | 1 byte | 0x99
