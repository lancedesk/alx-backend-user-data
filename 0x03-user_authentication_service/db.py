#!/usr/bin/env python3
"""
Database module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session
from user import Base, User


class DB:
    """
    Database class
    """

    def __init__(self) -> None:
        """
        Initialize a new Database instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """
        Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Add a user to the database.

        Args:
            email (str): The user's email address.
            hashed_password (str): The user's hashed password.

        Returns:
            User: The user instance added to the database.
        """
        new_user = User(email=email, hashed_password=hashed_password)
        self._session.add(new_user)
        self._session.commit()
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """Find a user by arbitrary keyword arguments.

        Args:
            kwargs: Arbitrary keyword arguments to filter the query.

        Returns:
            User: The first user instance matching the criteria.

        Raises:
            NoResultFound: If no user is found.
            InvalidRequestError: If invalid query arguments are passed.
        """
        user = self._session.query(User).filter_by(**kwargs).first()
        if user is None:
            raise NoResultFound()
        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """Update a user's attributes.

        Args:
            user_id (int): The ID of the user to update.
            kwargs: Arbitrary keyword arguments of attributes to update.

        Raises:
            ValueError: If an attribute to update is invalid.
        """
        user: User = self.find_user_by(id=user_id)
        for key in kwargs:
            if hasattr(user, key):
                setattr(user, key, kwargs[key])
            else:
                raise ValueError()
        self._session.commit()
