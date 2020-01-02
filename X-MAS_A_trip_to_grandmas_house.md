# X-MAS CTF 2019

## Forensic

### A trip to grandma's house




#### Analyse préliminaire 

Le challenge nous fait télécharger un fichier `.vdi` _Virtual Box Virtual DIsk_, ceci étant confirmé en vérifiant le magic byte du fichier via la commande `file` : 

```bash
[...]@root:~/Téléchargements/xmas# ls -lh |grep vdi
-rw-r--r--  1 root     root     1,3G déc.  15 19:36 Hard Drive.vdi
[...]@root:~/Téléchargements/xmas# file Hard\ Drive.vdi 
Hard Drive.vdi: VirtualBox Disk Image, major 1, minor 1 (<<< Oracle VM VirtualBox Disk Image >>>), 5368709120 bytes
```

En général, quand je récupère un disque de VM j'effectue deux actions :

1. Je créé une copie en image brute dans le cas où j'aurais besoin de réaliser des analyses fines (timeline, montage ...etc)

```bash
[...]@root:~/Téléchargements/xmas# VBoxManage clonehd --format RAW Hard\ Drive.vdi hdd.img
0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...
[...]
[...]@root:~/Téléchargements/xmas# file hdd.img 
hdd.img: DOS/MBR boot sector MS-MBR 9M english at offset 0x10+0xFF "Invalid partition table. Setup cannot continue." at offset 0x13f "Error loading operating system. Setup cannot continue." at offset 0x175, created with driveID 0x80 at 1:23:40; partition 1 : ID=0xb, active, start-CHS (0x0,1,1), end-CHS (0x28b,254,63), startsector 63, 10474317 sectors
```
2. J'identifie le système d'exploitation :

```bash
[...]@root:~/Téléchargements/xmas# strings Hard\ Drive.vdi |grep -Ei "(windows|linux)" |grep version
[...]
descriptionWhen you installed Windows 98, Setup saved information about your previous version of Windows. These files take up a large amount of disk space. If you are sure you do not want to return to your previous version of Windows, you should delete these files.
[...]
```

Visiblement on est sur du Windows 98, ça va être fun :-)

#### Analyse à chaud

Histoire de comprendre un peu qu'est ce qu'ils veulent qu'on foutent avec un Windows vieux de 20 ans, j'ai décidé de monter le disque virtuel sur une VM : 

![](https://i.imgur.com/VF3BLkH.png)

Bon il fallait s'y attendre, une mire d'authentification : 

![](https://i.imgur.com/uHaHDxJ.png)

Qu'est ce que cela m'a appris ? 

- Un potentiel utilisateur : __Thomas__.
- Que l'on cherche un mot de passe pour quelque chose qui est en minuscule et sans espaces. Le mot de passe de la session ?

#### Les vieux systèmes

![](https://media.giphy.com/media/bskFHBGO2WHKw/giphy.gif)


Bon, visiblement je dois trouver un mot de passe. Mais l'accès au système m'est impossible.

En y reflechissant, je me souvenais des commentaires de mon paternel sur la sécurité des systèmes des années 90 : _... Tu sais une fois que tu peux monter le volume c'est finit..._

Je me souvenais qu'il avait bon nombre de logiciels pour faire sauter des mots de passes de sessions Windows chez des clients, dont un linux bootable dont il se servait pour monter le volume de la partition principale.

![](https://i.imgur.com/uYT3A1H.png)


Je me suis alors dit que du fait que les systèmes des années 90 était fait pour être facile d'utilisation, facile à maintenir, surtout pour pouvoir se démocratiser auprès des entreprises. 

La gestion système des mots de passes doit être rudimentaire, un fichiers de mots de passes ? (les contrôleurs de domaines de nos jours stockents bien les mots de passes domaines dans un fichier `.dat` donc bon)

En surfant un peu sur la toile de l'interweb, j'ai finis par tomber sur un post vieux de 19 ans (sans Internet Wayback Machine, étonnant)

Source : [Windows 98 password](https://www.techrepublic.com/forums/discussions/windows-98-password-1/)

" _You can go to the DOS prompt. From_

_C:\windows type del *.pwl_
_If you want to bypass the login prompt altogether,under Network_ _Neighborhood, Change your primary network logon to "Windows Logon" and_ _reboot. At the next login prompt just hit enter without username &_ _password._ "

Bon bah visiblement c'est ce que je pensais, la réputation de gruyère que traine Microsoft Windows depuis les années 90 se vérifie. Il suffit de localiser le fichier de mot de passe de l'utilisateur (Thomas ?) et le supprimer.

#### Aké la naza

![](https://media.giphy.com/media/ZHlGzvZb130nm/giphy.gif)

Visiblement j'avais eu une bonne intuition de copier une image brute du disque pour des investiguations plus fines.

Etant donné que je n'ai pas eu de soucis à lancer ma VM et pour rechercher des chaines de caractères dans le disque, il n'est donc pas chiffré.

On va donc monter le disque, localiser le fichier `.pwl`, le virer et faire une copie `.vdi` du disque.

1. Identifier le point de départ de la partition MS-DOS :

```bash
[...]@root:~/Téléchargements/xmas# fdisk -l hdd.img
Disk hdd.img: 5 GiB, 5368709120 bytes, 10485760 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00000000

Device     Boot Start      End  Sectors Size Id Type
hdd.img1   *       63 10474379 10474317   5G  b W95 FAT32
```

Calcul de l'offset : [START] * [BLOCK_SIZE] = [OFFSET]

Donc : 63 * 512 = 32256 octets.

2. Monter la partition

```bash
[...]@root:~/Téléchargements/xmas# mount -o loop,offset=32256 hdd.img /mnt/win98/
[...]@root:~/Téléchargements/xmas# ls -l /mnt/win98/
total 1248
-rwxr-xr-x  1 root root      0 nov.   6  1996  AUTOEXEC.BAT
-rwxr-xr-x  1 root root      0 nov.   6  1996  autoexec.sdd
-rwxr-xr-x  1 root root  38403 nov.   6  1996  BOOTLOG.PRV
-rwxr-xr-x  1 root root  47458 nov.   6  1996  BOOTLOG.TXT
-rwxr-xr-x  1 root root  93890 avril 23  1999  COMMAND.COM
-rwxr-xr-x  1 root root      0 nov.   6  1996  CONFIG.SYS
-rwxr-xr-x  1 root root  69517 nov.  24 01:26  DETLOG.TXT
-rwxr-xr-x  1 root root   1010 nov.  24 01:24  FRUNLOG.TXT
-r-xr-xr-x  1 root root    660 nov.   6  1996  io32.sys
-r-xr-xr-x  1 root root 222390 avril 23  1999  IO.SYS
-rwxr-xr-x  1 root root     22 nov.  24 01:20  MSDOS.---
-r-xr-xr-x  1 root root   1676 nov.  24 01:26  MSDOS.SYS
drwxr-xr-x  3 root root   4096 nov.   6  1996 'My Documents'
-rwxr-xr-x  1 root root  10441 nov.   6  1996  NETLOG.TXT
drwxr-xr-x 20 root root   4096 nov.  24 01:20 'Program Files'
drwxr-xr-x  4 root root   4096 nov.  24 01:48  RECYCLED
-rwxr-xr-x  1 root root 114080 nov.   6  1996  SETUPLOG.TXT
-r-xr-xr-x  1 root root   5166 nov.  24 01:23  SUHDLOG.DAT
-r-xr-xr-x  1 root root 585760 nov.  24 01:23  SYSTEM.1ST
-rwxr-xr-x  1 root root  32768 nov.   6  1996  VIDEOROM.BIN
drwxr-xr-x 40 root root  12288 nov.  24 01:20  WINDOWS
```

3. Recherche du fichier `.pwl`

```bash
[...]@root:~/Téléchargements/xmas# find /mnt/win98/ -iname *.pwl
/mnt/win98/WINDOWS/THOMAS.PWL
[...]@root:~/Téléchargements/xmas# file /mnt/win98/WINDOWS/THOMAS.PWL
/mnt/win98/WINDOWS/THOMAS.PWL: data
[...]@root:~/Téléchargements/xmas# strings  /mnt/win98/WINDOWS/THOMAS.PWL
qsdi
\Wc1|E
```

Trouvé !

On supprime : 

```bash
[...]@root:~/Téléchargements/xmas# rm /mnt/win98/WINDOWS/THOMAS.PWL
```

On refait un disque `.vdi` pour relancer la VM : 

```bash
[...]@root:~/Téléchargements/xmas# VBoxManage convertdd hdd.img hdd.vdi --format VDI
Converting from raw image file="hdd.img" to file="hdd.vdi"...
Creating dynamic image with size 5368709120 bytes (5120MB)...
```

Et on le monte sur la bécanne : 

![](https://i.imgur.com/Ssq9wpg.png)

Bon, ça marche pas.

![](https://i.imgur.com/1wwQxON.png)

Le problème est visiblement de type ICC _Interface Chaise-Clavier_ (ou encore Couche 8 du modèle OSI).

Malgrès ma formation d'ingénieur Réseaux et Télécommunications, je ne suis pas foutu de distinguer une mire d'authentification réseau d'une mire système.

![](https://i.imgur.com/OctiX05.png)

Bon, reprenons le post des années 2000, il nous parle d'authentification réseau : 

" _under Network_ _Neighborhood, Change your primary network logon to "Windows Logon" and_ _reboot. At the next login prompt just hit enter without username &_ _password._ "

Je n'ai pas accès au paramétrage du système. Je pourrais à l'instar du fichier de condensats des mots de passes, modifier des fichiers (XAML surement) de configuration pour obtenir ce changement. Mais il faut penser plus simple.

Qu'est ce qui est neccessaire à une authentification réseau ? Une carte réseau pardi ! Selon ma théorie, si l'authentification réseau est aussi trouée que l'authentification système, retirer le moyen d'authentification réseau forcera le système à _failover_ sur l'authentification système.

_Windows be like_
![](https://media.giphy.com/media/NrkbD26EKNTlS/giphy.gif)

#### Aké la naza 2

1. On supprime la carte

![](https://i.imgur.com/L26zo3P.png)

2. On reboot.. et bon ça marche .____.

![](https://i.imgur.com/PUF6jVz.png)

#### Bon on fait quoi maintenant ?

__/!\ Information très importante :__ quand j'ai démarré le système, la première chose que j'ai fait est de foutre en bordel tout les fichiers `.txt` sur le bureau parce que c'est marrant. Ce qui on ve voir, m'a fait perdre BEAUCOUP de temps.

Qu'est ce qu'on voit sur le bureau ?

![](https://i.imgur.com/z5j5VAj.png)


- Des `.txt` en bordel (là ils sont bien mis mais j'avais tout bazardé).
- Une démo d'Age of Empire II (très bon choix).
- Un lecteur multimédia (Winamp).
- Outlook.
- MSN.
- Scitech Display Doctor pour fix les problèmes de couleurs des écrans.
- Un utilitaire Truecrypt.

![](https://media.giphy.com/media/u5C6s7LDK7G9y/giphy.gif)

Le mot de passe doit donc être celui d'un container Truecrypt chiffré quelque part sur le système.

Je vais utiliser un petit outil bien utile pour les challenges forensic, `tchuntng` qui vérifie si la taille des fichiers est modulo 512 octets, conséquence de la création d'un volume chiffré : 

```bash
[...]@root:~/Téléchargements/xmas# find /mnt/win98 -type f -name "*" |xargs -I% tchuntng "%"
/mnt/win98/WINDOWS/Application Data/Mozilla/Firefox/Profiles/3uswuz65.default/Cache/9C3F77C5d01
/mnt/win98/WINDOWS/Desktop/secret.txt
```

Visiblement il s'agit du même fichier qui a du être téléchargé dans la VM lors de la création du challenge : 

```bash
[...]@root:~/Téléchargements/xmas# ls -lh "/mnt/win98/WINDOWS/Application Data/Mozilla/Firefox/Profiles/3uswuz65.default/Cache/9C3F77C5d01"
-rwxr-xr-x 1 root root 24M nov.  24 14:48 '/mnt/win98/WINDOWS/Application Data/Mozilla/Firefox/Profiles/3uswuz65.default/Cache/9C3F77C5d01'
[...]@root:~/Téléchargements/xmas# ls -lh "/mnt/win98/WINDOWS/Desktop/secret.txt"
-rwxr-xr-x 1 root root 24M nov.  24 14:48 /mnt/win98/WINDOWS/Desktop/secret.txt
```

C'est cool, j'ai le container, mais sans mot de passe on va pas très loin.

#### 10 minutes later

![](https://media.giphy.com/media/GgSaCpfj6mAZq/giphy.gif)

Après une absence cérébrale d'environ dix minutes, je me suis dit qu'il fallait se repencher sur le bureau.

En effet, en scrutant mieux dans le bordel que j'avais mis dans les `.txt`, j'ai finis par distinguer des lettres.

Les deux éléments qui m'ont aussi mis la puce à l'oreille sont : 

- 1er indique sur le bureau.
- 
![](https://i.imgur.com/5TppzTB.png)

- Le troll de l'auteur.
- 
![](https://i.imgur.com/VljXPY6.png)

J'ai donc dû refaire TOUTES les manipulations précédentes pour retrouver les placements d'origines des fichiers `.txt`.

Petite morale de l'histoire, le digital forensic (autopsie numérique) ne s'appelle pas comme ça pour rien, quand on enquête il ne faut pas jouer avec le cadavre (bon nous on a des backup donc ça va mais imaginez le légiste).

#### Le déchiffrement

Après l'illumination, il est temps de déchiffrer ce que l'auteur a tenté d'écrire sur ce bureau, moi j'y vois quatre possibilités : 

1. `nysekritd4tvm`
2. `mysekritd4tvm`
3. `nysekritd4tum`
4. `mysekritd4tum`

![](https://i.imgur.com/hjtTdR0.png)

__/!\\__ Attention au mappage clavier, je préfère taper les mots de passes dans un fichier notepad dans le système pour éviter les erreurs.

Bon ça tombe bien, on a l'utilitaire sur le bureau pour déchiffrer le volume.

![](https://i.imgur.com/KhMEvPr.png)


Bingo, c'était le quatrième mot de passe `mysekritd4tum` : 

![](https://i.imgur.com/81Gynzk.png)

#### Qu'est ce que tu essayes de me dire challenge ?

Qu'est ce que c'est que ce bordel ?

On constate des fichiers/répertoires : 

- region
- playerdata
- players
- data
- session
- level

ça ressemble vachement à la backup d'un jeu.

En regardant la structure des fichiers, ça ne ressemble pas du tout à la structure des fichiers __d'Age of Empire II__.

On va analyser ça à froid.

#### Et c'est pas finit

On a quoi là dedans ? 

```bash
[...]@root:/mnt/win98/WINDOWS/Desktop/bordel# tree
.
├── data
│	└── villages.dat
├── DIM-1
├── DIM1
├── level.dat
├── level.dat_mcr
├── level.dat_old
├── playerdata
├── players
│	└── amyliff.dat
├── region
│	├── r.0.0.mca
│	├── r.0.-1.mca
│	├── r.-1.0.mca
│	├── r.1.0.mca
│	├── r.-1.-1.mca
│	├── r.1.-1.mca
│	├── r.1.1.mca
│	├── r.2.0.mca
│	├── r.2.-1.mca
│	├── r.2.1.mca
│	├── r.3.0.mca
│	├── r.3.-1.mca
│	├── r.4.0.mca
│	└── r.4.-1.mca
└── session.lock

6 directories, 20 files
```

Bon je passe mes autres péripéties de recherche sur le système, en faisant une petite recherche Google, j'ai finis par découvrir que les fichiers `.mca` et `.mcr` correspondent respectivement à des fichiers _Minecraft Anchor / Regions_.

En gros, ce sont les chunks d'une backup de map Minecraft.

J'ai donc décidé de la charger dans mon jeu histoire de voir à quoi la carte ressemble.

```bash
[...]@root:~/.minecraft/saves# cp -R /mnt/win98/WINDOWS/Desktop/bordel .
[...]@root:~/.minecraft/saves# ls -l
total 23524
drwxr-xr-x  8 root root    4096 janv.  2 13:42  bordel
drwxr-xr-x 12 root root    4096 déc.  16 07:27  mca
drwxr-xr-x 11 root root    4096 janv.  2 13:40 'New World'
-rwxr-xr-x  1 root root 2121728 déc.  16 07:27  r.0.0.mca
-rwxr-xr-x  1 root root 1556480 déc.  16 07:27  r.0.-1.mca
-rwxr-xr-x  1 root root  307200 déc.  16 07:27  r.-1.0.mca
-rwxr-xr-x  1 root root 2326528 déc.  16 07:27  r.1.0.mca
-rwxr-xr-x  1 root root  331776 déc.  16 07:27  r.-1.-1.mca
-rwxr-xr-x  1 root root 1318912 déc.  16 07:27  r.1.-1.mca
-rwxr-xr-x  1 root root   94208 déc.  16 07:27  r.1.1.mca
-rwxr-xr-x  1 root root 1474560 déc.  16 07:27  r.2.0.mca
-rwxr-xr-x  1 root root 1318912 déc.  16 07:27  r.2.-1.mca
-rwxr-xr-x  1 root root   16384 déc.  16 07:27  r.2.1.mca
-rwxr-xr-x  1 root root 3256320 déc.  16 07:27  r.3.0.mca
-rwxr-xr-x  1 root root 2547712 déc.  16 07:27  r.3.-1.mca
-rw-r--r--  1 root root   57344 déc.  16 07:27  r.3.1.mca
-rwxr-xr-x  1 root root 3293184 déc.  16 07:27  r.4.0.mca
-rwxr-xr-x  1 root root 2613248 déc.  16 07:27  r.4.-1.mca
-rw-r--r--  1 root root  401408 déc.  16 07:27  r.4.1.mca
-rw-r--r--  1 root root  475136 déc.  16 07:27  r.5.0.mca
-rw-r--r--  1 root root  434176 déc.  16 07:27  r.5.-1.mca
-rw-r--r--  1 root root  131072 déc.  16 07:27  r.5.1.mca
```

et ça charge correctement la backup : 

![](https://i.imgur.com/IiCMZ70.png)


Bon et je m'en doutais, une flatmap bedrock.

![](https://i.imgur.com/AYmyKfW.png)

Reflechissons, si j'étais un tordu qui veux planquer un flag dans des backup d'une map minecraft cachée dans un volume Truecrypt sur le disque d'une VM Windows 98, qu'est ce que je ferais ?

Etonnament la réponse m'a parue évidente : je dessinerais le flag en pixel art sur plusieurs chunks de la map pour que cela ne soit visible qu'avec un éditeur de chunk.

Après encore moult péripéties à batailler avec Java pour installer des utilitaires d'éditions de chunks (MCEdit et cie) sur mon système Linux (ne faite pas ça, svp, Gradle et la rétrocompatibilité des binaires JVM vont vous faire roter du sang).

Au final, je me suis dis que tout bon serveur minecraft qui se respecte doit avoir une fonction de visualisation des maps sur son site. Il y a donc forcément un autre tordu qui a dû développer une librairie JavaScript histoire de lire des chunks minecraft dans un navigateur.

Bingo, je suis tombé sur le site d'un chinois qui s'était amusé à le développer (c'est stylé d'ailleurs) : 

Chunk viewer : http://www.xiaoji-chen.com/2017/minecraft-chunk-viewer

Il m'a alors suffit de drop, one-by-one les chunks afin de trouver le flag : 

![](https://i.imgur.com/kr4dNJ5.png)

![](https://i.imgur.com/PvNsp0h.png)

![](https://i.imgur.com/NunI1ke.png)

![](https://i.imgur.com/z73eL8I.png)

De la stone sur de la bedrock en plus.

#### Conclusion

![](https://media.giphy.com/media/zCq3TyuABrRrG/giphy.gif)

Un challenge franchement sympatoche, bien tordu comme je les aimes et plutôt abordable avec du recul.
