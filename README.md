# CCDCMCS
C.C.D.C.M.C.S. alternatively known as the CCDC Mini Comp Scripts consist of scripts for mini comp (crazy IK). 

\#IAmTheLoneSurvivor
\#HiSlyvatoslav
\#IAmTheWinner

 copy & paste the following:
 ```
git clone https://github.com/AlecStar1/CCDCMCS.git
cd ./CCDCMCS
py -c "import os, sys; print(sys.platform); os.system('bash ./linux/main.sh' if sys.platform != 'win32' else 'powershell -ExecutionPolicy Bypass -File ./windows/main.ps1')"
 ```
should work regardless of system ran on, unless ofc it doesn't have python of which now you need to:  
run `./linux/main.sh` on linux  
run `powershell -ExecutionPolicy Bypass -File ./windows/main.ps1` on windows
