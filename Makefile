.PHONY: check-storage-layout deploy update-storage-layout

check-storage-layout:
	@bash shell/check_storage_layout.sh

update-storage-layout:
	forge inspect StateOracle storage-layout --json > .storage-layout
	@echo "Storage layout snapshot updated."

deploy:
	./shell/deploy_wizard.sh
