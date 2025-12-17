import data.pipeline

deny[msg] {
	# Find all stages that are Deployments ...
	input.pipeline.stages[i].stage.type == "Approval"
}