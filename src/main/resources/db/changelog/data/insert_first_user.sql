INSERT INTO USERS(id,username, email,password,created_at, updated_at,enabled) VALUES
(1,'admin','admin@gmail.com','$2a$10$zf9yq3WFfIg.OiQP/ud0l.3l.ipQhRxB7c9r5eT.AxwOkHyDYN/NS','2024-01-01 00:00:00','2024-01-01 00:00:00',true);


insert into user_role (user_id, role_id) values
(1, 1 ),
(1, 2 );