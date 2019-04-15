# hydra-consent-app-go

**This is a fork of the old [hydra-consent-app-go](https://github.com/ory/hydra-consent-app-go), updated to work with ORY Hydra >= 1.0.0**

This is a simple consent app for Hydra written in Go. It uses the Hydra SDK.

```bash
go get -u -d github.com/gregdhill/hydra-consent-app-go
cd $GOPATH/src/github.com/gregdhill/hydra-consent-app-go
```

Next open a shell and tell docker to start Hydra in the background:

```bash
./setup.sh
```

If you're in the project's directory:

```bash
go run main.go
```

Then, open the browser:

```
open http://localhost:3000/
```

Now follow the steps described in the browser. If you encounter an error,
use the browser's back button to get back to the last screen.

Keep in mind that you will not be able to refresh the callback url, as the
authorize code is valid only once. Also, this application needs to run on
port 4445 in order for the demo to work. Usually the consent endpoint won't
perform the authorize code, but for the sake of the demo we added that too.
