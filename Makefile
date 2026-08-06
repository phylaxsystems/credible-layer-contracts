.PHONY: check-storage-layout update-storage-layout check-abi update-abi

check-storage-layout:
	@bash shell/check_storage_layout.sh

update-storage-layout:
	forge inspect StateOracle storage-layout --json > .storage-layout
	@echo "Storage layout snapshot updated."

check-abi:
	@bash shell/check_abi.sh

update-abi:
	@bash shell/check_abi.sh --update
