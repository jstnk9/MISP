# Sigma Galaxy

This is the galaxy that I've created to map sigma rules into galaxies in MISP. Once the galaxy is uploaded, it looks like this.

Blog explanation: https://jstnk9.github.io/jstnk9/blog/Sigma-Rules-as-MISP-galaxies

# Script Usage

Python3 is needed. First install the requirements.txt, I recommend the use of virtualenv for this purpose.

```
pip install -r requirements.txt
```

After that, you can execute the script with the folder of your sigma rules as parameter.

Example for Windows
```
python sigma-to-galaxy.py -p "C:\github\sigma\rules" -r 
```

Example for Linux
```
python sigma-to-galaxy.py -p "/opt/sigma/rules/" -r 
```

If there are sigma rules with the same title, you can see those in the terminal printed. In that case, I recommend to modify the title, since it will generate some problems in your MISP.

# Images

![image](https://user-images.githubusercontent.com/7794663/202035331-e7c83586-3ab1-43b2-8ab4-c2a78cfd527d.png)

![image](https://user-images.githubusercontent.com/7794663/202035430-b1b53a2f-f3b7-4ae5-a585-51446487ff4c.png)

![image](https://user-images.githubusercontent.com/7794663/202035476-579f43e0-8d7e-45e0-aa16-bf7dbc4ed834.png)

You can add this galaxy to some specific MISP Object and attribute

![image](https://user-images.githubusercontent.com/7794663/202035936-980ca681-6603-4073-875a-124e9df735ac.png)

Or you can add this galaxy at the event level

![image](https://user-images.githubusercontent.com/7794663/202036117-9eadc450-9477-4864-839d-08690e8ae9e4.png)

