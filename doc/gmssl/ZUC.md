##  Algorithm and computational example 1
### Test Vector 1 (All 0)
Input:

Secret key k: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Initiate vector iv: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Output:

z<sub>1</sub>:27bedc74

z<sub>2</sub>:018082da

Initiation:

Linear feedback shift register(LFSR)state:


|i       | s<sub>0+i</sub>| s<sub>1+i</sub>| s<sub>2+i</sub>| s<sub>3+i</sub>| s<sub>4+i</sub>| s<sub>5+i</sub>| s<sub>6+i</sub>| s<sub>7+i</sub>|
| ------ | -------:| -------:| -------:| -------:| -------:| -------:| -------:| -------:|  
|0       |0044d700 |0026bc00 |00626b00 |00135e00 |00578900 |0035e200 |00713500 |0009af00 |
|8       |004d7800 |002f1300 |006bc400 |001af100 |005e2600 |003c4d00 |00789a00 |0047ac00 |
|t       |X<sub>0</sub>|X<sub>1</sub>|X<sub>2</sub>|X<sub>3</sub>|R<sub>1</sub>|R<sub>2</sub>|W|S<sub>15</sub>|
|0       |008f9a00 | f100005e| af00006b| 6b000089| 67822141| 62a3a55f| 008f9a00| 4563cb1b| 
|1       |8ac7ac00 | 260000d7| 780000e2| 5e00004d| 474a2e7e| 119e94bb| 4fc932a0| 28652aOf| 
|2       |50cacb1b | 4d000035| 13000013| 890000c4| c29687a5| e9b6eb51| 291f7a20| 7464f744| 
|3       |e8c92aOf | 9a0000bc| c400009a| e2000026| 29c272f3| 8cac7f5d| 141698fb| 3f5644ba| 
|4       |7eacf744 | ac000078| f1o00o5c| 350000af| 2c85a655| 24259cb0| e41b0514| 006a144c| 
|5       |00d444ba | cb1b00f1| 260000d7| af00006b| cbfbc5c0| 44c10b3a| 50777f9f| 07038b9b| 
|6       |0e07144c | 2aOf008f| 4d000035| 780000e2| e083c8d3| 7abf7679| 0abddcc6| 69b90c2b| 
|7       |d3728b9b | f7448ac7| 9a0000bc| 13000013| 147e14f4| b669e72d| aebOb9c1| 62a913ca| 
|8       |c5520e2b | 44ba50ca| ac000078| c400009a| 982834ao| f095d694| 8796020c| 7b591cc0| 
|9       |f6b213ea | 144ce8c9| cb1b00f1| f100005e| e14727d6| d0225869| 5f2ffdde| 70e21147|

LFSR state after initiation:

|i       | s<sub>0+i</sub>| s<sub>1+i</sub>| s<sub>2+i</sub>| s<sub>3+i</sub>| s<sub>4+i</sub>| s<sub>5+i</sub>| s<sub>6+i</sub>| s<sub>7+i</sub>|
| ------ | -------:| -------:| -------:| -------:| -------:| -------:| -------:| -------:|  
|0       | 7ce15b8b| 747caOc4| 6259ddOb| 47a94c2b| 3a89c82e| 32b433fc| 231ea13f| 31711c42| 
|8       | 4ccce955| 3fb6071e| 161d3512| 7114b136| 5154d452| 78c69a74| 4f26ba6b| 3e1b8d6a|

Finite state machine(FSM)internal state:

R<sub>1</sub>=14cfd44c 

R<sub>2</sub>=8c6de800

Key stream:

|t       |X<sub>0</sub>|X<sub>1</sub>|X<sub>2</sub>|X<sub>3</sub>|R<sub>1</sub>|R<sub>2</sub>|W|S<sub>15</sub>|
| ------ | -------:| -------:| -------:| -------:| -------:| -------:| -------:| -------:| 
|0       | 7c37ba16| b1367f6c| 1e426568| ddObf9c2| 3512bf50| a0920453| 286dafe5| 7f08e141| 
|1       | fe118d6a| d4522c3a| e955463d| 4c2be8f9| c7ee7f13| 0cOfa817| 27bede74| 3d383d04| 
|2       | 7a70e141| 9a74e229| 071e62e2| c82ec4b3| dde63da7| b9dd6a41| 018082da| 13d6d780|

### Test Vector 2 (All 1)
Input:

Secret key k: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff

Initiate vector iv: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff

Output:

z<sub>1</sub>:0657cfa0

z<sub>2</sub>:7096398b

Initiation:

Linear feedback shift register(LFSR)state:


|i       | s<sub>0+i</sub>| s<sub>1+i</sub>| s<sub>2+i</sub>| s<sub>3+i</sub>| s<sub>4+i</sub>| s<sub>5+i</sub>| s<sub>6+i</sub>| s<sub>7+i</sub>|
| ------ | -------:| -------:| -------:| -------:| -------:| -------:| -------:| -------:|  
|0       |7fc4d7ff |7fa6bcff |7fe26bff |7f935cff |7fd789ff |7fb5e2ff |7ff135ff |7f89afff |
|8       |7fcd78ff |7faf13ff |7febc4ff |7f9af1ff |7fde26ff |7fbc4dff |7ff89aff |7fc7acff |
|t       |X<sub>0</sub>|X<sub>1</sub>|X<sub>2</sub>|X<sub>3</sub>|R<sub>1</sub>|R<sub>2</sub>|W|S<sub>15</sub>|
|0       |ff8f9aff | f100005e| af00006b| 6b000089| b51c2110| 30a3629a| ff8f9aff| 76e49a1a| 
|1       |edc9acff | 26ffffd7| 78ffffe2| 5effff4d| a75b6f4b| 1a079628| 8978f089| 5e2d8983| 
|2       |bc5b9a1a | 4dffff35| 13ffff13| 89ffffc4| 9810b315| 99296735| 35088b79| 5b9484b8| 
|3       |b7298983 | 9affffbc| c4ffff9a| e2ffff26| 4c5bd8eb| 2d577790| c862a1cb| 2db5c755| 
|4       |5b6b84b8 | acffff78| f1ffff5e| 35ffffaf| a13dcb66| 21d0939f| 4487d3e3| 60579232| 
|5       |cOafc755 | 9a1afff1| 26ffffd7| afffff6b| cc5ce260| 0c50a8e2| 83629fd2| 29d4e960| 
|6       |53a99232 | 8983ff8f| 4dffff35| 78ffffe2| dada0730| b516b128| ac461934| 5e02d9e5| 
|7       |bc05e960 | 84b8edc9| 9affffbc| 13ffff13| 2bbe53a4| 12a8a16e| 1bf69f78| 7904dddc| 
|8       |f209d9e5 | c755bc5b| acffff78| c4ffff9a| 4a90d661| d9c744b4| ec602baf| 0c3c9016| 
|9       |1879dddc | 9232b729| 9a1afff1| f1ffff5e| 76bc13d7| a49ea404| 2cb05071| 0b9d257b|

LFSR state after initiation:

|i       | s<sub>0+i</sub>| s<sub>1+i</sub>| s<sub>2+i</sub>| s<sub>3+i</sub>| s<sub>4+i</sub>| s<sub>5+i</sub>| s<sub>6+i</sub>| s<sub>7+i</sub>|
| ------ | -------:| -------:| -------:| -------:| -------:| -------:| -------:| -------:|  
|0       |09a339ad |1291d190 |25554227 |36c09187 |0697773b |443cf9cd |6a4cd899 |49c34bd0 |
|8       |56130b14 |20e8f24c |7a5b1dcc |0c3cc2d1 |1cc082c8 |7f5904a2 |55b61ce8 |1fe46106 |
Finite state machine(FSM)internal state:

R<sub>1</sub>=b8017bd5 

R<sub>2</sub>=9ce2de5c

Key stream:

|t       |X<sub>0</sub>|X<sub>1</sub>|X<sub>2</sub>|X<sub>3</sub>|R<sub>1</sub>|R<sub>2</sub>|W|S<sub>15</sub>|
| ------ | -------:| -------:| -------:| -------:| -------:| -------:| -------:| -------:| 
|0       |3fc81cc8 |c2d141d1 |4bd08879 |42271346 |aa131b11 |09d7706c |668b56df |13f56dbf |
|1       |27ea6106 |82c8f4b6 |0b14d499 |91872523 |251e7804 |caac5d66 |0657cfa0 |0c0fe353 |
|2       |181f6dbf |04a21879 |f24c93c6 |773b4aaa |d94e9228 |91d88fba |7096398b |10f1eecf |


### Test Vector 3 (Random)
Input:

Secret key k: :3d 4c 4b e9 6a 82 fd ae b5 8f 64 1d b1 7b 45 5b

Initiate vector iv: 84 31 9a a8 de 69 15 ca 1f 6b da 6b fb d8 c7 66

Output:

z<sub>1</sub>:14f1c272

z<sub>2</sub>:3279c419

Initiation:

Linear feedback shift register(LFSR)state:


|i       | s<sub>0+i</sub>| s<sub>1+i</sub>| s<sub>2+i</sub>| s<sub>3+i</sub>| s<sub>4+i</sub>| s<sub>5+i</sub>| s<sub>6+i</sub>| s<sub>7+i</sub>|
| ------ | -------:| -------:| -------:| -------:| -------:| -------:| -------:| -------:|  
|0       |1ec4d784 |2626bc31 |25e26b9a |74935ea8 |355789de |4135e269 |7ef13515 |5709afca |
|8       |5acd781f |47af136b |326bc4da |0e9af16b |58de26fb |3dbc4dd8 |22f89ac7 |2dc7ac66 |
|t       |X<sub>0</sub>|X<sub>1</sub>|X<sub>2</sub>|X<sub>3</sub>|R<sub>1</sub>|R<sub>2</sub>|W|S<sub>15</sub>|
|0       |5b8f9ac7 | f16b8f5e| afca826b| 6b9a3d89| 9c62829f| 5df00831| 5b8f9ac7| 3c7b93c0| 
|1       |78f7ac66 | 26fb64d7| 781ffde2| 5ea84c4d| 3d533f3a| 80ff1faf| 4285372a| 41901ee9| 
|2       |832093c0 | 4dd81d35| 136bae13| 89de4bc4| 2ca57e9d| d1db72f9| 3f72cca9| 411efa99| 
|3       |823d1ee9 | 9ac7b1bc| c4dab59a| e269c926| 0e8dc40f| 60921a4f| 8073d36d| 24b3f49f| 
|4       |4967fa99 | ac667b78| f16b8f5e| 35156aaf| 16c81467| da8e7d8a| a87c58e5| 74265785| 
|5       |e84cf49f | 93c045f1| 26fb64d7| afca826b| 50c9eaa4| 3c3b2dfd| d9135c82| 481c5b9d| 
|6       |90385785 | 1ce95b8f| 4dd81d35| 781ffde2| 59857b80| be0fbdc1| fd2ceb1e| 4b7f87ed| 
|7       |96ff5b9d | fa9978f7| 9ac7b1bc| 136bae13| 9528f8ea| bcc7f7eb| 8d89dddc| 0e633ce7| 
|8       |1cc687ed | f49f832o| ac667b78| c4dab59a| c59d2932| e1098a64| 46b676f2| 643ac5a6| 
|9       |c8753ce7 | 5785823d| 93c045f1| f16b8f5e| 755cbac8| 3f9c6c86| eef1ao39| 625ac5d7|

LFSR state after initiation:

|i       | s<sub>0+i</sub>| s<sub>1+i</sub>| s<sub>2+i</sub>| s<sub>3+i</sub>| s<sub>4+i</sub>| s<sub>5+i</sub>| s<sub>6+i</sub>| s<sub>7+i</sub>|
| ------ | -------:| -------:| -------:| -------:| -------:| -------:| -------:| -------:|  
|0       |10da5941 |5b6acbf6 |17060ce1 |35368174 |5cf4385a |479943df |2753bab2 |73775d6a | 
|8       |43930a37 |77b4af31 |15b2e89f |24ff6c20 |740c40b9 |026a5503 |194b2a57 |7a9a1cff |
Finite state machine(FSM)internal state:

R<sub>1</sub>=860a7dfa 

R<sub>2</sub>=bfOeOffc

Key stream:

|t       |X<sub>0</sub>|X<sub>1</sub>|X<sub>2</sub>|X<sub>3</sub>|R<sub>1</sub>|R<sub>2</sub>|W|S<sub>15</sub>|
| ------ | -------:| -------:| -------:| -------:| -------:| -------:| -------:| -------:| 
|0       |f5342a57 |6e20cf69 |5d6a8f32 |0ce121b4 |129d8b39 |2d7cdcc1 |3ead461d |3d4aa9e7 |
|1       |7a951cff |40b92b65 |0a374ea7 |8174b6d5 |ab7cf688 |c1598aa6 |14f1c272 |71db1828 |
|2       |e3b6a9e7 |550349fe |af31e6ee |385a2eOc |3cec1a4a |9053ccOc |3279c419 |258937da |

##  Algorithm and computational example 2(Data Privacy)

The following is an example of the algorithm. All the data is using 16 hexadecimal representation. 

The 1st set of encryption examples:

CK = 17 3d 14 ba 50 03 73 1d 7a 60 04 94 70 f0 0a 29 

COUNT = 66035492

BEARER = f

DIRECTION = 0

LENGTH = c1

IBS:

6cf65340 735552ab 0c9752fa 6f9025fe Obd675d9 005875b2 00000000 

OBS:

a6c85fc6 6afb8533 aafc2518 dfe78494 0ee1e4b0 30238cc8 00000000

The 2nd set of encryption examples:

CK = e5 bd 3c a0 eb 55 ad e8 66 c6 ac 58 bd 54 30 2a 

COUNT = 56823

BEARER = 18

DIRECTION = 1

LENGTH = 320

IBS:

14a8ef69 3d678507 bbe7270a 7f67ff50 06c3525b 9807e467 c4e56000 ba338f5d 42955903 67518222
46c80d3b 38f07f4b e2d8ff58 05f51322 29bde93b bbdcaf38 2bf1ee97 2fbf9977 bada8945 847a2a6c
9ad34a66 7554e04d 1f7fa2c3 3241bd8f 01ba220d

OBD:
131d43eO dea1be5c 5a1bfd97 1d852cbf 712d7b4f 57961£ea 3208afa8 bca433f4 56ad09c7 417e58bc
69cf8866 d1353f74 865e8078 1d202dfb 3ecff7fc bc3b190f e82a204e d0e350fc 0f6f2613 b2f2bca6
df5a473a 57a4a00d 985ebad8 80d6f238 64a07b01

The 3rd set of encryption examples:

CK =e1 3f ed 21 b4 6e 4e 7e c3 12 53 b2 bb 17 b3 e0 

COUNT = 2738cdaa 

BEARER = 1a 

DIRECTION = 0

LENCTH =FB3

IBS:

8d74e20d 54894e06 d3cb13cb 3933065e 8674be62 adb1c72b 3a646965 ab63cb7b 7854dfdc 27e84929 
f49c64b8 72a490b1 3f957b64 827e71f4 1fbd4269 a42c97f8 24537027 f86e9f4a d82d1df4 51690fdd 
98b6d03f 3aOebe3a 312d6b84 0ba5a182 0b2a2c97 09c090d2 45ed267c f845ae41 fa975d33 33ac3009 
fd40eba9 eb5b8857 14b768b6 97138baf 21380eca 49f644d4 8689e421 5760b906 739fOd2b 3f091133 
ca15d981 cbe401ba f72d05ac e05cccb2 d297f4ef 6a5f58d9 1246cfa7 7215b892 ab441d52 78452795 
ccb7f5d7 9057a1c4 f77f80d4 6db2033c b79bedf8 e60551ce 10c667f6 2a97abaf abbcd677 2018df96 
a282ea73 7ce2cb33 1211f60d 5354ce78 f9918d9c 206ca042 c9b62387 dd709604 a50af16d 8d35a890 
6be484cf 2e74a928 99403643 53249b27 b4c9ae29 eddfc7da 6418791a 4e7baaO6 60fa6451 1f2d685c 
c3a5ff70 eOd2b742 92e3b8ao cd6b04b1 c790b8ea d2703708 540dea2f c09c3da7 70f65449 c84d817a 
4f551055 e19ab850 18a0028b 71a144d9 6791e9a3 57793350 4eee0060 340c69d2 74e1bf9d 805dcbcc 
1a6faa97 6800b6ff 2b671dc4 63652fa8 a33ee509 74c1c21b e01eabb2 16743026 9d72ee51 1c9dde30 
797c9a25 d86ce74f 5b961be5 fdfb68o7 814039e7 137636bd 1d7fa9e0 9efd2007 505906a5 ac45dfde 
ed7757bb ee745749 c2963335 0beeOea6 f409df45 80160000

OBS:

94eaa4aa 30a57137 ddf09b97 b25618a2 0a13e2f1 0fa5bf81 61a879cc 2ae797a6 b4cf2d9d f31debb9
905ccfec 97de605d 21c61ab8 531b7f3c 9da5f039 31f8a064 2de48211 f5f52ffe a10f392a 04766998
5da454a2 8fO80961 a6c2b62d aa17f33c d60a4971 f48d2d90 9394a55f 48117ace 43d708e6 b77d3dc4
6d8bc017 d4d1abb7 7b7428c0 42b06f2f 99d8d07c 9879d996 00127a31 985f1099 bbd7d6c1 519ede8f
5eeb4a61 0b349ac0 1ea23506 91756bd1 05c974a5 3eddb35d 1d4100b0 12e522ab 41f4c5f2 fde76b59
cb8b96d8 85cfe408 0d1328a0 d636ccOe dc05800b 76acca8f ef672o84 d1f52a8b bd8e0993 320992c7
ffbae17c 408441e0 ee883fc8 a8b05e22 f5ff7f8d 1b48c74c 468c467a 028f09fd 7ce91109 a570a2d5
c4d5f4fa 18c5dd3e 4562afe2 4ef77190 1f59af64 5898acef 088abae0 7e92d52e b2de5504 5bb1b7c4
164ef2d7 a6cac15e eb926d7e a2f08b66 elf759f3 aee44614 725aa3c7 482b3084 4c143ff8 5b53f1e5
83c50125 7dddd096 b81268da a303f172 34c23335 41f0bb8e 190648c5 807c866d 71932286 09adb948
686f7de2 94a802cc 38f7fe52 08f5ea31 96d0167b 9bdd02f0 d2a5221c a508f893 af5c4b4b b9f4f520
fd84289b 3dbe7e61 497a7e2a 584037ea 637b6981 127174af 57b471df 4b2768fd 79c1540f b3edf2ea
22cb69be c0cf8d93 3d9c6fdd 645e8505 91cca3d6 2c0cc000



##  Algorithm and computational example 3 (Data Integrity)

The following is an example of the algorithm. All the data is using 16 hexadecimal representation. 

The 1st set of encryption examples:

IK = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

COUNT = 0

BEARER = 0

DIRECTION = 0

LENGTH = 1

M:00000000

MAC:c8a9595e

The 2nd set of encryption examples:

IK = c9 e6 ce c4 60 7c 72 db 00 0a ef a8 83 85 ab 0a

COUNT = a94059da

BEARER = a

DIRECTION = a

LENGTH = 241

M:

983b41d4 7d780c9e 1ad11d7e b70391b1 de0b35da 2dc62f83 e7b78d63 06ca0ea0 7e941b7b
e91348f9 fcb170e2 217fecd9 7f9f68ad b16e5d7d 21e569d2 80ed775c ebde3f40 93c53881
00000000

MAC:fae8ff0b

The 3rd set of encryption examples:

IK = 6b 8b 08 ee 79 eO b5 98 2d 6d 12 8e a9 f2 20 cb

COUNT = 561eb2dd

BEARER = 1c

DIRECTION = 0

LENGTH = 1626

M:

5bad7247 10ba1c56 d5a315f8 d40f6e09 3780be8e 8de07b69 92432018 e08ed96a 5734af8b
ad8a575d 3a1f162f 85045cc7 70925571 d9f5b94e 454a77c1 6e72936b fO16ae15 7499fO54 
3b5d52ca a6dbeab6 97d2bb73 e41b8075 dce79b4b 86044f66 1d4485a5 43dd7860 6eO419e8 
059859d3 cb2b67ce 0977603f 81ff839e 33185954 4cfbc8d0 0fef1a4c 8510fb54 7d6b06c6 
11ef44f1 boo107cf a45a06aa b360152b 28dc1ebe 6f7feO9b 0516f9a5 b02a1bd8 4bb0181e 
2e89e19b d8125930 d178682f 3862dc51 b636f04e 720c47c3 ce51ad70 d94b9b22 55fbae90 
6549f499 f8c6d399 47ed5e5d f8e2def1 13253e7b 08dOa76b 6bfc68c8 12f375c7 9b8fe5fd 
85976aa6 d46b4a23 39d8ae51 47f680fb e70f978b 38effd7b 2f7866a2 2554e193 a94e98a6 
8b74bd25 bb2b3f5f bOa5fd59 887f9ab6 8159b717 8d5b7b67 7cb546bf 41eadca2 16fc1085 
0128f8bd ef5c8d89 f96afa4f a8b54885 565ed838 a950fee5 f1c3bOa4 f6fb71e5 4dfd169e 
82cecc72 66c850e6 7c5efOba 960f5214 060e71eb 172a75fc 1486835c bea65344 65bO55c9
6a72e410 52241823 25d83041 4b40214d aa8091d2 eOfb01oa e15c6de9 o850973b df1e423b
e148a237 b87aOc9f 34d4b476 05b803d7 43a86a90 399a4af3 96d3a120 0a62f3d9 507962e8
e5bee6d3 da2bb3f7 237664ac 7a292823 900bc635 03b29e80 d63f6067 bf8e1716 ac25beba
350deb62 a99feO31 85eb4f69 937ecd38 7941fda5 44ba67db 09117749 38bO1827 bcc69c92
b3f772a9 d2859ef0 03398b1f 6bbad7b5 74f7989a 1d10b2df 798eOdbf 30d65874 64d24878
cd00cOea ee8a1a0c c753a279 79e11b41 db1de3d5 038afaf4 9f5c682c 3748d8a3 a9ec54e6
a371275f 168351of 8e4f9093 8f9ab6e1 34c2cfdf 4841cba8 8eOcff2b 0bcc8e6a dcb71109
b5198fec f1bb7e5c 531aca50 a56a8a3b 6de59862 d41fa113 d9cd9578 o8f08571 d9a4bb79
2af271f6 cc6dbb8d c7ec36e3 6be1ed30 8164c31c 7cOafc54 1c000000
03b29e80 d63f6067 bf8e1716

MAC:0ca12792


