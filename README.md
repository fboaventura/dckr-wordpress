# fboaventura/dckr-wordpress

Docker instance to run wordpress with some additional apache modules, such as remoteip, alias, deflate and others not provided on the official wordpress images.

## How to use

This instance is published at [Docker Hub](https://hub.docker.com/r/fboaventura/dckr-wordpress/), so it's publicly available.  All you need to run this instance is:

```bash
$ docker run -d -v `pwd`:/app/www -p 8080:80 fboaventura/dckr-wordpress
```
Once the instance is running, all you have to do is open a web browser and point it to `http://${DOMAIN}:8080`

