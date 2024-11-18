from app import app, db


# import json

# def lambda_handler(event, context):
#     # TODO implement
    
#     if __name__ == '__main__':
#         with app.app_context():
#             db.create_all()  # Create tables if they don't exist
#         app.run(debug=True)

#     return {
#         'statusCode': 200,
#         'body': json.dumps(app)
#     }


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)
