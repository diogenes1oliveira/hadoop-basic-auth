.PHONY: deploy/staging
deploy/staging:
	mvn --batch-mode -DskipTests -DautoReleaseAfterClose=false -Pdeploy deploy

.PHONY: deploy/prod
deploy/prod:
	mvn --batch-mode -DskipTests -DautoReleaseAfterClose=true -Pdeploy deploy

.PHONY: dev/version
dev/version:
	@grep -F '<version>' pom.xml | tr -d '[:space:]' | tr '<>/' '|' | cut -d'|' -f 3
