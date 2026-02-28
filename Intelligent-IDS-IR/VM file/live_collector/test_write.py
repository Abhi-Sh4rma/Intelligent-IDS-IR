path = r"\\vmware-host\Shared Folders\shared_logs\normalized_auth.log"

print("Attempting write to:", path)

with open(path, "a", encoding="utf-8") as f:
    f.write("TEST_WRITE_FROM_VM\n")

print("Write completed")
