Perfect! On **Linux**, the setup is slightly different but straightforward. Here’s the full step-by-step guide for your blockchain + device wipe workflow.

---

## **Step 1: Install Python 3**

Check if Python is installed:

```bash
python3 --version
```

If not installed, install Python 3 and pip:

**Debian/Ubuntu:**

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv -y
```

**Fedora/RHEL:**

```bash
sudo dnf install python3 python3-pip python3-venv -y
```

---

## **Step 2: Create a virtual environment**

Go to your project directory:

```bash
cd ~/ZeroTrace
```

Create a virtual environment named `venv`:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

* Your prompt should now show `(venv)` at the beginning.

---

## **Step 3: Upgrade pip**

```bash
pip install --upgrade pip
```

---

## **Step 4: Install dependencies**

Your Python script needs:

* `fastapi` → for API server
* `cryptography` → for signing & verifying
* `uvicorn` → for running FastAPI server

Install them:

```bash
pip install fastapi cryptography uvicorn
```

Optional (for HTTP requests / JSON handling if needed):

```bash
pip install requests
```

---

## **Step 5: Test environment**

Run Python and test imports:

```bash
python
>>> import fastapi
>>> import cryptography
>>> import uvicorn
>>> exit()
```

No errors = environment ready.

---

## **Step 6: Run your script (optional test)**

```bash
python device_wipe_blockchain.py
```

* This should run your full sequential workflow: wipe → certificate → blockchain.

---

## **Step 7: Integrate with C (Linux)**

If calling Python from C using `system()`:

```c
#include <stdlib.h>
int main() {
    system("/home/username/ZeroTrace/venv/bin/python /home/username/ZeroTrace/device_wipe_blockchain.py");
    return 0;
}
```

* Replace `username` with your Linux user.
* This ensures C calls the Python script **using the virtual environment**.

---

### ✅ **Tip**

* Always activate the virtual environment in your shell before testing.
* When calling from C, **use the full path to `python` in `venv/bin/python`**.

---

If you want, I can **write a single Linux shell script** that sets up everything, installs dependencies, and tests your Python blockchain workflow automatically.

Do you want me to do that?
