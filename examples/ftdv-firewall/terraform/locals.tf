locals {
  policy_display_name = "${var.policy_name}-${var.environment}"

  # dCloud segment labels used in rule names / comments
  dcloud_outside_label = "Default-Network"
  dcloud_inside_label  = "Private"
}
