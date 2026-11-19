package com.veracode.verademo.commands;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

public class RemoveAccountCommand implements BlabberCommand {
	private static final Logger logger = LogManager.getLogger("VeraDemo:RemoveAccountCommand");

	private Connection connect;

	public RemoveAccountCommand(Connection connect, String username) {
		super();
		this.connect = connect;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.veracode.verademo.commands.Command#execute()
	 */
	@Override
	public void execute(String blabberUsername) {
		String sqlQuery = "DELETE FROM listeners WHERE blabber=? OR listener=?;";
		logger.info(sqlQuery);
		PreparedStatement action;
		try {
			action = connect.prepareStatement(sqlQuery);

			action.setString(1, blabberUsername);
			action.setString(2, blabberUsername);
			action.execute();

			/* START EXAMPLE VULNERABILITY */
			// Use try-with-resources to ensure Statement and ResultSet are properly closed (CWE-404)
			sqlQuery = "SELECT blab_name FROM users WHERE username = ?";
			try {
				logger.info("SELECT blab_name FROM users WHERE username = " + URLEncoder.encode(blabberUsername, "UTF-8"));
			} catch (UnsupportedEncodingException e1) {
				logger.info("SELECT blab_name FROM users WHERE username = [encoding error]");
			}
			try (PreparedStatement selectStatement = connect.prepareStatement(sqlQuery)) {
				selectStatement.setString(1, blabberUsername);
				try (ResultSet result = selectStatement.executeQuery()) {
					result.next();

					String event = "Removed account for blabber " + result.getString(1);
					sqlQuery = "INSERT INTO users_history (blabber, event) VALUES (?, ?)";
					try {
						logger.info("INSERT INTO users_history (blabber, event) VALUES (" + URLEncoder.encode(blabberUsername, "UTF-8") + ", " + URLEncoder.encode(event, "UTF-8") + ")");
					} catch (UnsupportedEncodingException e1) {
						logger.info("INSERT INTO users_history (blabber, event) VALUES ([encoding error], [encoding error])");
					}
					try (PreparedStatement insertStatement = connect.prepareStatement(sqlQuery)) {
						insertStatement.setString(1, blabberUsername);
						insertStatement.setString(2, event);
						insertStatement.execute();
					}

					sqlQuery = "DELETE FROM users WHERE username = ?";
					try {
						logger.info("DELETE FROM users WHERE username = " + URLEncoder.encode(blabberUsername, "UTF-8"));
					} catch (UnsupportedEncodingException e1) {
						logger.info("DELETE FROM users WHERE username = [encoding error]");
					}
					try (PreparedStatement deleteStatement = connect.prepareStatement(sqlQuery)) {
						deleteStatement.setString(1, blabberUsername);
						deleteStatement.execute();
					}
				}
			}
			/* END EXAMPLE VULNERABILITY */

		} catch (SQLException e) {
			e.printStackTrace();
		}
	}
}
