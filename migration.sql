CREATE SCHEMA banking_stage_results;

CREATE TABLE banking_stage_results.transaction_infos (
  signature CHAR(88) NOT NULL,
  message text,
  errors text,
  is_executed BOOL,
  is_confirmed BOOL,
  first_notification_slot BIGINT NOT NULL,
  cu_requested BIGINT,
  prioritization_fees BIGINT,
  time_of_first_notification BIGINT, 
);

CREATE TABLE banking_stage_results.blocks (
  block_hash text not null,
  notification_timestamp BIGINT,
  confirmed_timestamp BIGINT,
  number_of_transactions BIGINT,
  number_of_transactions BIGINT,
  total_cu BIGINT,
  cu_by_accounts text,
)
