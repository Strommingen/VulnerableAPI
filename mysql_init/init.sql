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

insert into Users (user_id, username, password) values (1,'admin', '$2a$10$OZ4pInlYooTQ2gnWhILYPOWZ6XNEJuMtKAk2BrXAYZuUdid3m0n0S');
insert into Users (user_id,username, password) values (2,'kalle', '$2a$10$XBp4EFXOgvuGq4kZ5d/7qOR7dDz9CbcN8xwprCOmvqXupMnFnP13m');

insert into Tasks (task_name,description,status,user_id) values ("Hashing","Add functionality to hash passwords","completed","1");

insert into Tasks (task_name,description,status,user_id) values ("Taxes","Declare my taxes","in progress","2");
insert into Tasks (task_name,description,status,user_id) values ("Studying","Study how to make more secure passwords","in progress","2");
insert into Tasks (task_name,description,status,user_id) values ("Laundry","Do the laundry","completed","2");