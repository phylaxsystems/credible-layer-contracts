.PHONY: check-storage-layout deploy update-storage-layout check-abi

check-storage-layout:
	@bash shell/check_storage_layout.sh

update-storage-layout:
	forge inspect StateOracle storage-layout --json > .storage-layout
	@echo "Storage layout snapshot updated."

# Compares against ABI_BASE_REF, defaulting to origin/main.
check-abi:
	@bash shell/check_abi.sh $(ABI_BASE_REF)

deploy:
	./shell/deploy_wizard.sh
