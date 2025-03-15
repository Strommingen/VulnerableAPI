create database if not exists vdb;
use vdb;

create table if not exists Users(
    user_id integer not null auto_increment primary key,
    username varchar(20) not null unique,
    password varchar(60) not null
);

create table if not exists Tasks(
    task_id integer not null auto_increment primary key,
    task_name varchar(20) not null,
    description varchar(100) not null,
    status varchar(20) not null,
    user_id integer not null, foreign key (user_id) references Users(user_id)
);

insert into Users (user_id,username, password) values (1,'kalle', '$2a$10$v3oIsDFnYbKXbdpyIEOrxOrPWootxN3BNSPPwSxvZSgC4VVPawMg2'); -- kalle, password
insert into Users (user_id, username, password) values (2,'admin', '$2a$10$OZ4pInlYooTQ2gnWhILYPOWZ6XNEJuMtKAk2BrXAYZuUdid3m0n0S'); -- admin veryS0t40ngPasforA8mi-n

insert into Tasks (task_name,description,status,user_id) values (
    "adminTask",
    "",
    "in progress",
    "2");