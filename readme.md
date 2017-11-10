scripts back up from shiyu.pro

##  Step1-SSR

```
wget https://raw.githubusercontent.com/githubfeatures/ssrbackup/master/ssr.sh && bash ssr.sh
```

##  Step2-BBR

```
wget https://raw.githubusercontent.com/githubfeatures/ssrbackup/master/bbr.sh && bash bbr.sh
```

when it's done, reboot and use the following command to check if BBR is running

```
lsmod | grep bbr
```
